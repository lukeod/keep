"""Database operations for alert."""

import json

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import UUID
import uuid

from dateutil.parser import parse
from dateutil.tz import tz
from psycopg2.errors import NoActiveSqlTransaction
from sqlalchemy import (
    String,
    and_,
    case,
    cast,
    desc,
    func,
    literal,
    null,
    or_,
    select,
    text,
    union,
    update,
)
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import joinedload, subqueryload
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.sql import exists
from sqlalchemy.sql.functions import count
from sqlmodel import Session, col, or_, select, text

from keep.api.core.db._common import (
    Session,
    engine,
    logger,
    retry_on_db_error,
    existed_or_new_session,
    get_json_extract_field,
    __convert_to_uuid,
)
from keep.api.models.alert import AlertStatus
from keep.api.models.db.incident import IncidentSeverity, IncidentStatus
from keep.api.models.db.alert import *
from keep.api.models.db.workflow import (
    Workflow,
    WorkflowExecution,
    WorkflowToAlertExecution,
    WorkflowToIncidentExecution,
)
from keep.api.models.action_type import ActionType


def add_audit(
    tenant_id: str,
    fingerprint: str,
    user_id: str,
    action: ActionType,
    description: str,
    session: Session = None,
    commit: bool = True,
) -> AlertAudit:
    with existed_or_new_session(session) as session:
        audit = AlertAudit(
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            user_id=user_id,
            action=action.value,
            description=description,
        )
        session.add(audit)
        if commit:
            session.commit()
            session.refresh(audit)
    return audit


@retry_on_db_error
def add_alerts_to_incident(
    tenant_id: str,
    incident: Incident,
    fingerprints: List[str],
    is_created_by_ai: bool = False,
    session: Optional[Session] = None,
    override_count: bool = False,
    exclude_unlinked_alerts: bool = False,  # if True, do not add alerts to incident if they are manually unlinked
    max_retries=3,
) -> Optional[Incident]:
    logger.info(
        f"Adding alerts to incident {incident.id} in database, total {len(fingerprints)} alerts",
        extra={"tags": {"tenant_id": tenant_id, "incident_id": incident.id}},
    )
    with existed_or_new_session(session) as session:
        with session.no_autoflush:
            # Use a set for faster membership checks
            existing_fingerprints = set(
                session.exec(
                    select(LastAlert.fingerprint)
                    .join(
                        LastAlertToIncident,
                        and_(
                            LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                            LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                        ),
                    )
                    .where(
                        LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                        LastAlertToIncident.tenant_id == tenant_id,
                        LastAlertToIncident.incident_id == incident.id,
                    )
                ).all()
            )
            new_fingerprints = {
                fingerprint
                for fingerprint in fingerprints
                if fingerprint not in existing_fingerprints
            }
            # filter out unlinked alerts
            if exclude_unlinked_alerts:
                unlinked_alerts = set(
                    session.exec(
                        select(LastAlert.fingerprint)
                        .join(
                            LastAlertToIncident,
                            and_(
                                LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                                LastAlertToIncident.fingerprint
                                == LastAlert.fingerprint,
                            ),
                        )
                        .where(
                            LastAlertToIncident.deleted_at != NULL_FOR_DELETED_AT,
                            LastAlertToIncident.tenant_id == tenant_id,
                            LastAlertToIncident.incident_id == incident.id,
                        )
                    ).all()
                )
                new_fingerprints = new_fingerprints - unlinked_alerts
            if not new_fingerprints:
                return incident
            alert_to_incident_entries = [
                LastAlertToIncident(
                    fingerprint=str(fingerprint),  # it may sometime be UUID...
                    incident_id=incident.id,
                    tenant_id=tenant_id,
                    is_created_by_ai=is_created_by_ai,
                )
                for fingerprint in new_fingerprints
            ]
            for idx, entry in enumerate(alert_to_incident_entries):
                session.add(entry)
                if (idx + 1) % 100 == 0:
                    logger.info(
                        f"Added {idx + 1}/{len(alert_to_incident_entries)} alerts to incident {incident.id} in database",
                        extra={
                            "tags": {"tenant_id": tenant_id, "incident_id": incident.id}
                        },
                    )
                    session.flush()
            session.commit()
            alerts_data_for_incident = get_alerts_data_for_incident(
                tenant_id, new_fingerprints, session
            )
            new_sources = list(
                set(incident.sources if incident.sources else [])
                | set(alerts_data_for_incident["sources"])
            )
            new_affected_services = list(
                set(incident.affected_services if incident.affected_services else [])
                | set(alerts_data_for_incident["services"])
            )
            if not incident.forced_severity:
                # If incident has alerts already, use the max severity between existing and new alerts,
                # otherwise use the new alerts max severity
                new_severity = (
                    max(
                        incident.severity,
                        alerts_data_for_incident["max_severity"].order,
                    )
                    if incident.alerts_count
                    else alerts_data_for_incident["max_severity"].order
                )
            else:
                new_severity = incident.severity
            if not override_count:
                alerts_count = (
                    select(count(LastAlertToIncident.fingerprint)).where(
                        LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                        LastAlertToIncident.tenant_id == tenant_id,
                        LastAlertToIncident.incident_id == incident.id,
                    )
                ).subquery()
            else:
                alerts_count = alerts_data_for_incident["count"]
            last_received_field = get_json_extract_field(
                session, Alert.event, "lastReceived"
            )
            started_at, last_seen_at = session.exec(
                select(func.min(last_received_field), func.max(last_received_field))
                .join(
                    LastAlertToIncident,
                    and_(
                        LastAlertToIncident.tenant_id == Alert.tenant_id,
                        LastAlertToIncident.fingerprint == Alert.fingerprint,
                    ),
                )
                .where(
                    LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                    LastAlertToIncident.tenant_id == tenant_id,
                    LastAlertToIncident.incident_id == incident.id,
                )
            ).one()
            if isinstance(started_at, str):
                started_at = parse(started_at)
            if isinstance(last_seen_at, str):
                last_seen_at = parse(last_seen_at)
            incident_id = incident.id
            for attempt in range(max_retries):
                try:
                    session.exec(
                        update(Incident)
                        .where(
                            Incident.id == incident_id,
                            Incident.tenant_id == tenant_id,
                        )
                        .values(
                            alerts_count=alerts_count,
                            last_seen_time=last_seen_at,
                            start_time=started_at,
                            affected_services=new_affected_services,
                            severity=new_severity,
                            sources=new_sources,
                        )
                    )
                    session.commit()
                    break
                except StaleDataError as ex:
                    if "expected to update" in ex.args[0]:
                        logger.info(
                            f"Phantom read detected while updating incident `{incident_id}`, retry #{attempt}"
                        )
                        session.rollback()
                        continue
                    else:
                        raise
            session.add(incident)
            session.refresh(incident)
            return incident


def bulk_upsert_alert_fields(
    tenant_id: str,
    fields: List[str],
    provider_id: str,
    provider_type: str,
    session: Optional[Session] = None,
    max_retries=3,
):
    with existed_or_new_session(session) as session:
        for attempt in range(max_retries):
            try:
                # Prepare the data for bulk insert
                data = [
                    {
                        "tenant_id": tenant_id,
                        "field_name": field,
                        "provider_id": provider_id,
                        "provider_type": provider_type,
                    }
                    for field in fields
                ]
                if engine.dialect.name == "postgresql":
                    stmt = pg_insert(AlertField).values(data)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=[
                            "tenant_id",
                            "field_name",
                        ],  # Unique constraint columns
                        set_={
                            "provider_id": stmt.excluded.provider_id,
                            "provider_type": stmt.excluded.provider_type,
                        },
                    )
                elif engine.dialect.name == "mysql":
                    stmt = mysql_insert(AlertField).values(data)
                    stmt = stmt.on_duplicate_key_update(
                        provider_id=stmt.inserted.provider_id,
                        provider_type=stmt.inserted.provider_type,
                    )
                elif engine.dialect.name == "sqlite":
                    stmt = sqlite_insert(AlertField).values(data)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=[
                            "tenant_id",
                            "field_name",
                        ],  # Unique constraint columns
                        set_={
                            "provider_id": stmt.excluded.provider_id,
                            "provider_type": stmt.excluded.provider_type,
                        },
                    )
                elif engine.dialect.name == "mssql":
                    # SQL Server requires a raw query with a MERGE statement
                    values = ", ".join(
                        f"('{tenant_id}', '{field}', '{provider_id}', '{provider_type}')"
                        for field in fields
                    )
                    merge_query = text(
                        f"""
                        MERGE INTO AlertField AS target
                        USING (VALUES {values}) AS source (tenant_id, field_name, provider_id, provider_type)
                        ON target.tenant_id = source.tenant_id AND target.field_name = source.field_name
                        WHEN MATCHED THEN
                            UPDATE SET provider_id = source.provider_id, provider_type = source.provider_type
                        WHEN NOT MATCHED THEN
                            INSERT (tenant_id, field_name, provider_id, provider_type)
                            VALUES (source.tenant_id, source.field_name, source.provider_id, source.provider_type)
                    """
                    )
                    session.execute(merge_query)
                else:
                    raise NotImplementedError(
                        f"Upsert not supported for {engine.dialect.name}"
                    )
                # Execute the statement
                if engine.dialect.name != "mssql":  # Already executed for SQL Server
                    session.execute(stmt)
                session.commit()
                break
            except OperationalError as e:
                # Handle any potential race conditions
                session.rollback()
                if "Deadlock found" in str(e):
                    logger.info(
                        f"Deadlock found during bulk_upsert_alert_fields `{e}`, retry #{attempt}"
                    )
                    if attempt >= max_retries:
                        raise e
                    continue
                else:
                    raise e


def count_alerts(
    provider_type: str,
    provider_id: str,
    ever: bool,
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    tenant_id: str,
):
    with Session(engine) as session:
        if ever:
            return (
                session.query(Alert)
                .filter(
                    Alert.tenant_id == tenant_id,
                    Alert.provider_id == provider_id,
                    Alert.provider_type == provider_type,
                )
                .count()
            )
        else:
            return (
                session.query(Alert)
                .filter(
                    Alert.tenant_id == tenant_id,
                    Alert.provider_id == provider_id,
                    Alert.provider_type == provider_type,
                    Alert.timestamp >= start_time,
                    Alert.timestamp <= end_time,
                )
                .count()
            )


def create_alert(tenant_id, provider_type, provider_id, event, fingerprint):
    with Session(engine) as session:
        alert = Alert(
            tenant_id=tenant_id,
            provider_type=provider_type,
            provider_id=provider_id,
            event=event,
            fingerprint=fingerprint,
        )
        session.add(alert)
        session.commit()
        session.refresh(alert)
        return alert


def dismiss_error_alerts(tenant_id: str, alert_id=None, dismissed_by=None) -> None:
    with Session(engine) as session:
        stmt = (
            update(AlertRaw)
            .where(
                AlertRaw.tenant_id == tenant_id,
            )
            .values(
                dismissed=True,
                dismissed_by=dismissed_by,
                dismissed_at=datetime.now(tz=timezone.utc),
            )
        )
        if alert_id:
            if isinstance(alert_id, str):
                alert_id_uuid = uuid.UUID(alert_id)
                stmt = stmt.where(AlertRaw.id == alert_id_uuid)
            else:
                stmt = stmt.where(AlertRaw.id == alert_id)
        session.exec(stmt)
        session.commit()


def enrich_alerts_with_incidents(
    tenant_id: str, alerts: List[Alert], session: Optional[Session] = None
):
    with existed_or_new_session(session) as session:
        alert_incidents = session.exec(
            select(LastAlertToIncident.fingerprint, Incident)
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                    LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                    LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                ),
            )
            .join(Incident, LastAlertToIncident.incident_id == Incident.id)
            .where(
                LastAlert.tenant_id == tenant_id,
                LastAlertToIncident.fingerprint.in_(
                    [alert.fingerprint for alert in alerts]
                ),
            )
        ).all()
        incidents_per_alert = defaultdict(list)
        for fingerprint, incident in alert_incidents:
            incidents_per_alert[fingerprint].append(incident)
        for alert in alerts:
            alert._incidents = incidents_per_alert[alert.fingerprint]
        return alerts


def enrich_incidents_with_alerts(
    tenant_id: str, incidents: List[Incident], session: Optional[Session] = None
):
    with existed_or_new_session(session) as session:
        incident_alerts = session.exec(
            select(LastAlertToIncident.incident_id, Alert)
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                    LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                    LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .where(
                LastAlert.tenant_id == tenant_id,
                LastAlertToIncident.incident_id.in_(
                    [incident.id for incident in incidents]
                ),
            )
        ).all()
        alerts_per_incident = defaultdict(list)
        for incident_id, alert in incident_alerts:
            alerts_per_incident[incident_id].append(alert)
        for incident in incidents:
            incident._alerts = alerts_per_incident[incident.id]
        return incidents


def get_alert_audit(
    tenant_id: str, fingerprint: str | list[str], limit: int = 50
) -> List[AlertAudit]:
    """
    Get the alert audit for the given fingerprint(s).
    Args:
        tenant_id (str): the tenant_id to filter the alert audit by
        fingerprint (str | list[str]): the fingerprint(s) to filter the alert audit by
        limit (int, optional): the maximum number of alert audits to return. Defaults to 50.
    Returns:
        List[AlertAudit]: the alert audit for the given fingerprint(s)
    """
    with Session(engine) as session:
        if isinstance(fingerprint, list):
            query = (
                select(AlertAudit)
                .where(AlertAudit.tenant_id == tenant_id)
                .where(AlertAudit.fingerprint.in_(fingerprint))
                .order_by(desc(AlertAudit.timestamp), AlertAudit.fingerprint)
            )
            if limit:
                query = query.limit(limit)
        else:
            query = (
                select(AlertAudit)
                .where(AlertAudit.tenant_id == tenant_id)
                .where(AlertAudit.fingerprint == fingerprint)
                .order_by(desc(AlertAudit.timestamp))
                .limit(limit)
            )
        # Execute the query and fetch all results
        result = session.execute(query).scalars().all()
    return result


def get_alert_by_event_id(
    tenant_id: str, event_id: str, session: Optional[Session] = None
) -> Alert:
    with existed_or_new_session(session) as session:
        query = (
            select(Alert)
            .filter(Alert.tenant_id == tenant_id)
            .filter(Alert.id == uuid.UUID(event_id))
        )
        query = query.options(subqueryload(Alert.alert_enrichment))
        alert = session.exec(query).first()
    return alert


def get_alert_by_fingerprint_and_event_id(
    tenant_id: str, fingerprint: str, event_id: str
) -> Alert:
    with Session(engine) as session:
        alert = (
            session.query(Alert)
            .filter(Alert.tenant_id == tenant_id)
            .filter(Alert.fingerprint == fingerprint)
            .filter(Alert.id == uuid.UUID(event_id))
            .first()
        )
    return alert


def get_alerts_by_fingerprint(
    tenant_id: str,
    fingerprint: str,
    limit=1,
    status=None,
    with_alert_instance_enrichment=False,
) -> List[Alert]:
    """
    Get all alerts for a given fingerprint.
    Args:
        tenant_id (str): The tenant_id to filter the alerts by.
        fingerprint (str): The fingerprint to filter the alerts by.
    Returns:
        List[Alert]: A list of Alert objects.
    """
    with Session(engine) as session:
        # Create the query
        query = session.query(Alert)
        # Apply subqueryload to force-load the alert_enrichment relationship
        query = query.options(subqueryload(Alert.alert_enrichment))
        if with_alert_instance_enrichment:
            query = query.options(subqueryload(Alert.alert_instance_enrichment))
        # Filter by tenant_id
        query = query.filter(Alert.tenant_id == tenant_id)
        query = query.filter(Alert.fingerprint == fingerprint)
        query = query.order_by(Alert.timestamp.desc())
        if status:
            query = query.filter(func.json_extract(Alert.event, "$.status") == status)
        if limit:
            query = query.limit(limit)
        # Execute the query
        alerts = query.all()
    return alerts


def get_alerts_by_ids(
    tenant_id: str, alert_ids: list[str | UUID], session: Optional[Session] = None
) -> List[Alert]:
    with existed_or_new_session(session) as session:
        query = (
            select(Alert)
            .filter(Alert.tenant_id == tenant_id)
            .filter(Alert.id.in_(alert_ids))
        )
        query = query.options(subqueryload(Alert.alert_enrichment))
        return session.exec(query).all()


def get_alerts_count(
    tenant_id: str,
) -> int:
    with Session(engine) as session:
        return (
            session.query(Alert)
            .filter(
                Alert.tenant_id == tenant_id,
            )
            .count()
        )


def get_alerts_data_for_incident(
    tenant_id: str,
    fingerprints: Optional[List[str]] = None,
    session: Optional[Session] = None,
):
    """
    Function to prepare aggregated data for incidents from the given list of alert_ids
    Logic is wrapped to the inner function for better usability with an optional database session
    Args:
        tenant_id (str): The tenant ID to filter alerts
        alert_ids (list[str | UUID]): list of alert ids for aggregation
        session (Optional[Session]): The database session or None
    Returns: dict {sources: list[str], services: list[str], count: int}
    """
    with existed_or_new_session(session) as session:
        fields = (
            get_json_extract_field(session, Alert.event, "service"),
            Alert.provider_type,
            Alert.fingerprint,
            get_json_extract_field(session, Alert.event, "severity"),
        )
        alerts_data = session.exec(
            select(*fields)
            .select_from(LastAlert)
            .join(
                Alert,
                and_(
                    LastAlert.tenant_id == Alert.tenant_id,
                    LastAlert.alert_id == Alert.id,
                ),
            )
            .where(
                LastAlert.tenant_id == tenant_id,
                col(LastAlert.fingerprint).in_(fingerprints),
            )
        ).all()
        sources = []
        services = []
        severities = []
        for service, source, fingerprint, severity in alerts_data:
            if source:
                sources.append(source)
            if service:
                services.append(service)
            if severity:
                if isinstance(severity, int):
                    severities.append(IncidentSeverity.from_number(severity))
                else:
                    severities.append(IncidentSeverity(severity))
        return {
            "sources": set(sources),
            "services": set(services),
            "max_severity": max(severities) if severities else IncidentSeverity.LOW,
        }


def get_alerts_fields(tenant_id: str) -> List[AlertField]:
    with Session(engine) as session:
        fields = session.exec(
            select(AlertField).where(AlertField.tenant_id == tenant_id)
        ).all()
    return fields


def get_alerts_metrics_by_provider(
    tenant_id: str,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    fields: Optional[List[str]] = [],
) -> Dict[str, Dict[str, Any]]:
    dynamic_field_sums = [
        func.sum(
            case(
                (
                    (func.json_extract(Alert.event, f"$.{field}").isnot(None))
                    & (func.json_extract(Alert.event, f"$.{field}") != False),
                    1,
                ),
                else_=0,
            )
        ).label(f"{field}_count")
        for field in fields
    ]
    with Session(engine) as session:
        query = (
            session.query(
                Alert.provider_type,
                Alert.provider_id,
                func.count(Alert.id).label("total_alerts"),
                func.sum(
                    case((LastAlertToIncident.fingerprint.isnot(None), 1), else_=0)
                ).label("correlated_alerts"),
                *dynamic_field_sums,
            )
            .join(LastAlert, Alert.id == LastAlert.alert_id)
            .outerjoin(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .filter(
                Alert.tenant_id == tenant_id,
            )
        )
        # Add timestamp filter only if both start_date and end_date are provided
        if start_date and end_date:
            query = query.filter(
                Alert.timestamp >= start_date, Alert.timestamp <= end_date
            )
        results = query.group_by(Alert.provider_id, Alert.provider_type).all()
    metrics = {}
    for row in results:
        key = f"{row.provider_id}_{row.provider_type}"
        metrics[key] = {
            "total_alerts": row.total_alerts,
            "correlated_alerts": row.correlated_alerts,
            "provider_type": row.provider_type,
        }
        for field in fields:
            metrics[key][f"{field}_count"] = getattr(row, f"{field}_count", 0)
    return metrics


def get_alerts_with_filters(
    tenant_id,
    provider_id=None,
    filters=None,
    time_delta=1,
    with_incidents=False,
) -> list[Alert]:
    with Session(engine) as session:
        # Create the query
        query = (
            session.query(Alert)
            .select_from(LastAlert)
            .join(Alert, LastAlert.alert_id == Alert.id)
        )
        # Apply subqueryload to force-load the alert_enrichment relationship
        query = query.options(subqueryload(Alert.alert_enrichment))
        # Filter by tenant_id
        query = query.filter(Alert.tenant_id == tenant_id)
        # Filter by time_delta
        query = query.filter(
            Alert.timestamp
            >= datetime.now(tz=timezone.utc) - timedelta(days=time_delta)
        )
        # Ensure Alert and AlertEnrichment are joined for subsequent filters
        query = query.outerjoin(Alert.alert_enrichment)
        # Apply filters if provided
        if filters:
            for f in filters:
                filter_key, filter_value = f.get("key"), f.get("value")
                if isinstance(filter_value, bool) and filter_value is True:
                    # If the filter value is True, we want to filter by the existence of the enrichment
                    #   e.g.: all the alerts that have ticket_id
                    if session.bind.dialect.name in ["mysql", "postgresql"]:
                        query = query.filter(
                            func.json_extract(
                                AlertEnrichment.enrichments, f"$.{filter_key}"
                            )
                            != null()
                        )
                    elif session.bind.dialect.name == "sqlite":
                        query = query.filter(
                            func.json_type(
                                AlertEnrichment.enrichments, f"$.{filter_key}"
                            )
                            != null()
                        )
                elif isinstance(filter_value, (str, int)):
                    if session.bind.dialect.name in ["mysql", "postgresql"]:
                        query = query.filter(
                            func.json_unquote(
                                func.json_extract(
                                    AlertEnrichment.enrichments, f"$.{filter_key}"
                                )
                            )
                            == filter_value
                        )
                    elif session.bind.dialect.name == "sqlite":
                        query = query.filter(
                            func.json_extract(
                                AlertEnrichment.enrichments, f"$.{filter_key}"
                            )
                            == filter_value
                        )
                    else:
                        logger.warning(
                            "Unsupported dialect",
                            extra={"dialect": session.bind.dialect.name},
                        )
                else:
                    logger.warning("Unsupported filter type", extra={"filter": f})
        if provider_id:
            query = query.filter(Alert.provider_id == provider_id)
        query = query.order_by(Alert.timestamp.desc())
        query = query.limit(10000)
        # Execute the query
        alerts = query.all()
        if with_incidents:
            alerts = enrich_alerts_with_incidents(tenant_id, alerts, session)
    return alerts


def get_all_alerts_by_fingerprints(
    tenant_id: str, fingerprints: List[str], session: Optional[Session] = None
) -> List[Alert]:
    with existed_or_new_session(session) as session:
        query = (
            select(Alert)
            .filter(Alert.tenant_id == tenant_id)
            .filter(Alert.fingerprint.in_(fingerprints))
            .order_by(Alert.timestamp.desc())
        )
        return session.exec(query).all()


def get_error_alerts(tenant_id: str, limit: int = 100) -> List[AlertRaw]:
    with Session(engine) as session:
        return (
            session.query(AlertRaw)
            .filter(
                AlertRaw.tenant_id == tenant_id,
                AlertRaw.error == True,
                AlertRaw.dismissed == False,
            )
            .limit(limit)
            .all()
        )


def get_first_alert_datetime(
    tenant_id: str,
) -> datetime | None:
    with Session(engine) as session:
        first_alert = (
            session.query(Alert)
            .filter(
                Alert.tenant_id == tenant_id,
            )
            .first()
        )
        if first_alert:
            return first_alert.timestamp


def get_incident_alerts_and_links_by_incident_id(
    tenant_id: str,
    incident_id: UUID | str,
    limit: Optional[int] = None,
    offset: Optional[int] = 0,
    session: Optional[Session] = None,
    include_unlinked: bool = False,
) -> tuple[List[tuple[Alert, LastAlertToIncident]], int]:
    with existed_or_new_session(session) as session:
        query = (
            session.query(
                Alert,
                LastAlertToIncident,
            )
            .select_from(LastAlertToIncident)
            .join(
                LastAlert,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident_id,
            )
            .order_by(col(LastAlert.timestamp).desc())
            .options(joinedload(Alert.alert_enrichment))
        )
        if not include_unlinked:
            query = query.filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
            )
    total_count = query.count()
    if limit is not None and offset is not None:
        query = query.limit(limit).offset(offset)
    return query.all(), total_count


def get_incident_alerts_by_incident_id(*args, **kwargs) -> tuple[List[Alert], int]:
    """
    Unpacking (List[(Alert, LastAlertToIncident)], int) to (List[Alert], int).
    """
    alerts_and_links, total_alerts = get_incident_alerts_and_links_by_incident_id(
        *args, **kwargs
    )
    alerts = [alert_and_link[0] for alert_and_link in alerts_and_links]
    return alerts, total_alerts


def get_incidents_by_alert_fingerprint(
    tenant_id: str, fingerprint: str, session: Optional[Session] = None
) -> List[Incident]:
    with existed_or_new_session(session) as session:
        alert_incidents = session.exec(
            select(Incident)
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                    LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                    LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                ),
            )
            .join(Incident, LastAlertToIncident.incident_id == Incident.id)
            .where(
                LastAlert.tenant_id == tenant_id,
                LastAlertToIncident.fingerprint == fingerprint,
            )
        ).all()
        return alert_incidents


def get_int_severity(input_severity: int | str) -> int:
    if isinstance(input_severity, int):
        return input_severity
    else:
        return IncidentSeverity(input_severity).order


def get_last_alert_by_fingerprint(
    tenant_id: str,
    fingerprint: str,
    session: Optional[Session] = None,
    for_update: bool = False,
) -> Optional[LastAlert]:
    with existed_or_new_session(session) as session:
        query = select(LastAlert).where(
            and_(
                LastAlert.tenant_id == tenant_id,
                LastAlert.fingerprint == fingerprint,
            )
        )
        if for_update:
            query = query.with_for_update()
        return session.exec(query).first()


def get_last_alert_hashes_by_fingerprints(
    tenant_id, fingerprints: list[str]
) -> dict[str, str | None]:
    # get the last alert hashes for a list of fingerprints
    # to check deduplication
    with Session(engine) as session:
        query = (
            select(LastAlert.fingerprint, LastAlert.alert_hash)
            .where(LastAlert.tenant_id == tenant_id)
            .where(LastAlert.fingerprint.in_(fingerprints))
        )
        results = session.execute(query).all()
    # Create a dictionary from the results
    alert_hash_dict = {
        fingerprint: alert_hash
        for fingerprint, alert_hash in results
        if alert_hash is not None
    }
    return alert_hash_dict


def get_last_alerts(
    tenant_id,
    provider_id=None,
    limit=1000,
    timeframe=None,
    upper_timestamp=None,
    lower_timestamp=None,
    with_incidents=False,
    fingerprints=None,
) -> list[Alert]:
    with Session(engine) as session:
        dialect_name = session.bind.dialect.name
        # Build the base query using select()
        stmt = (
            select(Alert, LastAlert.first_timestamp.label("startedAt"))
            .select_from(LastAlert)
            .join(Alert, LastAlert.alert_id == Alert.id)
            .where(LastAlert.tenant_id == tenant_id)
            .where(Alert.tenant_id == tenant_id)
        )
        if timeframe:
            stmt = stmt.where(
                LastAlert.timestamp
                >= datetime.now(tz=timezone.utc) - timedelta(days=timeframe)
            )
        # Apply additional filters
        filter_conditions = []
        if upper_timestamp is not None:
            filter_conditions.append(LastAlert.timestamp < upper_timestamp)
        if lower_timestamp is not None:
            filter_conditions.append(LastAlert.timestamp >= lower_timestamp)
        if fingerprints:
            filter_conditions.append(LastAlert.fingerprint.in_(tuple(fingerprints)))
        logger.info(f"filter_conditions: {filter_conditions}")
        if filter_conditions:
            stmt = stmt.where(*filter_conditions)
        # Main query for alerts
        stmt = stmt.options(subqueryload(Alert.alert_enrichment))
        if with_incidents:
            if dialect_name == "sqlite":
                # SQLite version - using JSON
                incidents_subquery = (
                    select(
                        LastAlertToIncident.fingerprint,
                        func.json_group_array(
                            cast(LastAlertToIncident.incident_id, String)
                        ).label("incidents"),
                    )
                    .where(
                        LastAlertToIncident.tenant_id == tenant_id,
                        LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                    )
                    .group_by(LastAlertToIncident.fingerprint)
                    .subquery()
                )
            elif dialect_name == "mysql":
                # MySQL version - using GROUP_CONCAT
                incidents_subquery = (
                    select(
                        LastAlertToIncident.fingerprint,
                        func.group_concat(
                            cast(LastAlertToIncident.incident_id, String)
                        ).label("incidents"),
                    )
                    .where(
                        LastAlertToIncident.tenant_id == tenant_id,
                        LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                    )
                    .group_by(LastAlertToIncident.fingerprint)
                    .subquery()
                )
            elif dialect_name == "postgresql":
                # PostgreSQL version - using string_agg
                incidents_subquery = (
                    select(
                        LastAlertToIncident.fingerprint,
                        func.string_agg(
                            cast(LastAlertToIncident.incident_id, String),
                            ",",
                        ).label("incidents"),
                    )
                    .where(
                        LastAlertToIncident.tenant_id == tenant_id,
                        LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                    )
                    .group_by(LastAlertToIncident.fingerprint)
                    .subquery()
                )
            else:
                raise ValueError(f"Unsupported dialect: {dialect_name}")
            stmt = stmt.add_columns(incidents_subquery.c.incidents)
            stmt = stmt.outerjoin(
                incidents_subquery,
                Alert.fingerprint == incidents_subquery.c.fingerprint,
            )
        if provider_id:
            stmt = stmt.where(Alert.provider_id == provider_id)
        # Order by timestamp in descending order and limit the results
        stmt = stmt.order_by(desc(Alert.timestamp)).limit(limit)
        # Execute the query
        alerts_with_start = session.execute(stmt).all()
        # Process results based on dialect
        alerts = []
        for alert_data in alerts_with_start:
            alert = alert_data[0]
            startedAt = alert_data[1]
            if not alert.event.get("startedAt"):
                alert.event["startedAt"] = str(startedAt)
            else:
                alert.event["firstTimestamp"] = str(startedAt)
            alert.event["event_id"] = str(alert.id)
            if with_incidents:
                incident_id = alert_data[2]
                if dialect_name == "sqlite":
                    # Parse JSON array for SQLite
                    incident_id = json.loads(incident_id)[0] if incident_id else None
                elif dialect_name in ("mysql", "postgresql"):
                    # Split comma-separated string for MySQL and PostgreSQL
                    incident_id = incident_id.split(",")[0] if incident_id else None
                alert.event["incident"] = str(incident_id) if incident_id else None
            alerts.append(alert)
        return alerts


def get_last_alerts_by_fingerprints(
    tenant_id: str,
    fingerprint: List[str],
    session: Optional[Session] = None,
) -> List[LastAlert]:
    with existed_or_new_session(session) as session:
        query = select(LastAlert).where(
            and_(
                LastAlert.tenant_id == tenant_id,
                LastAlert.fingerprint.in_(fingerprint),
            )
        )
        return session.exec(query).all()


def get_last_alerts_for_incidents(
    incident_ids: List[str | UUID],
) -> Dict[str, List[Alert]]:
    with Session(engine) as session:
        query = (
            session.query(
                Alert,
                LastAlertToIncident.incident_id,
            )
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id.in_(incident_ids),
            )
            .order_by(Alert.timestamp.desc())
        )
        alerts = query.all()
    incidents_alerts = defaultdict(list)
    for alert, incident_id in alerts:
        incidents_alerts[str(incident_id)].append(alert)
    return incidents_alerts


def get_last_workflow_workflow_to_alert_executions(
    session: Session, tenant_id: str
) -> list[WorkflowToAlertExecution]:
    """
    Get the latest workflow executions for each alert fingerprint.
    Args:
        session (Session): The database session.
        tenant_id (str): The tenant_id to filter the workflow executions by.
    Returns:
        list[WorkflowToAlertExecution]: A list of WorkflowToAlertExecution objects.
    """
    # Subquery to find the max started timestamp for each alert_fingerprint
    max_started_subquery = (
        session.query(
            WorkflowToAlertExecution.alert_fingerprint,
            func.max(WorkflowExecution.started).label("max_started"),
        )
        .join(
            WorkflowExecution,
            WorkflowToAlertExecution.workflow_execution_id == WorkflowExecution.id,
        )
        .filter(WorkflowExecution.tenant_id == tenant_id)
        .filter(WorkflowExecution.started >= datetime.now() - timedelta(days=7))
        .group_by(WorkflowToAlertExecution.alert_fingerprint)
    ).subquery("max_started_subquery")
    # Query to find WorkflowToAlertExecution entries that match the max started timestamp
    latest_workflow_to_alert_executions: list[WorkflowToAlertExecution] = (
        session.query(WorkflowToAlertExecution)
        .join(
            WorkflowExecution,
            WorkflowToAlertExecution.workflow_execution_id == WorkflowExecution.id,
        )
        .join(
            max_started_subquery,
            and_(
                WorkflowToAlertExecution.alert_fingerprint
                == max_started_subquery.c.alert_fingerprint,
                WorkflowExecution.started == max_started_subquery.c.max_started,
            ),
        )
        .filter(WorkflowExecution.tenant_id == tenant_id)
        .limit(1000)
        .all()
    )
    return latest_workflow_to_alert_executions


def get_previous_alert_by_fingerprint(tenant_id: str, fingerprint: str) -> Alert:
    # get the previous alert for a given fingerprint
    with Session(engine) as session:
        alert = (
            session.query(Alert)
            .filter(Alert.tenant_id == tenant_id)
            .filter(Alert.fingerprint == fingerprint)
            .order_by(Alert.timestamp.desc())
            .limit(2)
            .all()
        )
    if len(alert) > 1:
        return alert[1]
    else:
        # no previous alert
        return None


def get_workflow_executions_for_incident_or_alert(
    tenant_id: str, incident_id: str, limit: int = 25, offset: int = 0
):
    with Session(engine) as session:
        # Base query for both incident and alert related executions
        base_query = (
            select(
                WorkflowExecution.id,
                WorkflowExecution.started,
                WorkflowExecution.status,
                WorkflowExecution.execution_number,
                WorkflowExecution.triggered_by,
                WorkflowExecution.workflow_id,
                WorkflowExecution.execution_time,
                Workflow.name.label("workflow_name"),
                literal(incident_id).label("incident_id"),
                case(
                    (
                        WorkflowToAlertExecution.alert_fingerprint != None,
                        WorkflowToAlertExecution.alert_fingerprint,
                    ),
                    else_=literal(None),
                ).label("alert_fingerprint"),
            )
            .join(Workflow, WorkflowExecution.workflow_id == Workflow.id)
            .outerjoin(
                WorkflowToAlertExecution,
                WorkflowExecution.id == WorkflowToAlertExecution.workflow_execution_id,
            )
            .where(WorkflowExecution.tenant_id == tenant_id)
        )
        # Query for workflow executions directly associated with the incident
        incident_query = base_query.join(
            WorkflowToIncidentExecution,
            WorkflowExecution.id == WorkflowToIncidentExecution.workflow_execution_id,
        ).where(WorkflowToIncidentExecution.incident_id == incident_id)
        # Query for workflow executions associated with alerts tied to the incident
        alert_query = (
            base_query.join(
                LastAlert,
                WorkflowToAlertExecution.alert_fingerprint == LastAlert.fingerprint,
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident_id,
                LastAlert.tenant_id == tenant_id,
            )
        )
        # Combine both queries
        combined_query = union(incident_query, alert_query).subquery()
        # Count total results
        count_query = select(func.count()).select_from(combined_query)
        total_count = session.execute(count_query).scalar()
        # Final query with ordering, offset, and limit
        final_query = (
            select(combined_query)
            .order_by(desc(combined_query.c.started))
            .offset(offset)
            .limit(limit)
        )
        # Execute the query and fetch results
        results = session.execute(final_query).all()
        return results, total_count


def get_workflow_to_alert_execution_by_workflow_execution_id(
    workflow_execution_id: str,
) -> WorkflowToAlertExecution:
    """
    Get the WorkflowToAlertExecution entry for a given workflow execution ID.
    Args:
        workflow_execution_id (str): The workflow execution ID to filter the workflow execution by.
    Returns:
        WorkflowToAlertExecution: The WorkflowToAlertExecution object.
    """
    with Session(engine) as session:
        return (
            session.query(WorkflowToAlertExecution)
            .filter_by(workflow_execution_id=workflow_execution_id)
            .first()
        )


def is_alert_assigned_to_incident(
    fingerprint: str, incident_id: UUID, tenant_id: str
) -> bool:
    with Session(engine) as session:
        assigned = session.exec(
            select(LastAlertToIncident)
            .join(Incident, LastAlertToIncident.incident_id == Incident.id)
            .where(LastAlertToIncident.fingerprint == fingerprint)
            .where(LastAlertToIncident.incident_id == incident_id)
            .where(LastAlertToIncident.tenant_id == tenant_id)
            .where(LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT)
            .where(Incident.status != IncidentStatus.DELETED.value)
        ).first()
    return assigned is not None


def is_all_alerts_in_status(
    fingerprints: Optional[List[str]] = None,
    incident: Optional[Incident] = None,
    status: AlertStatus = AlertStatus.RESOLVED,
    session: Optional[Session] = None,
):
    if incident and incident.alerts_count == 0:
        return False
    with existed_or_new_session(session) as session:
        enriched_status_field = get_json_extract_field(
            session, AlertEnrichment.enrichments, "status"
        )
        status_field = get_json_extract_field(session, Alert.event, "status")
        subquery = (
            select(
                enriched_status_field.label("enriched_status"),
                status_field.label("status"),
            )
            .select_from(LastAlert)
            .join(Alert, LastAlert.alert_id == Alert.id)
            .outerjoin(
                AlertEnrichment,
                and_(
                    Alert.tenant_id == AlertEnrichment.tenant_id,
                    Alert.fingerprint == AlertEnrichment.alert_fingerprint,
                ),
            )
        )
        if fingerprints:
            subquery = subquery.where(LastAlert.fingerprint.in_(fingerprints))
        if incident:
            subquery = subquery.join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                    LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                ),
            ).where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident.id,
            )
        subquery = subquery.subquery()
        not_in_status_exists = session.query(
            exists(
                select(
                    subquery.c.enriched_status,
                    subquery.c.status,
                )
                .select_from(subquery)
                .where(
                    or_(
                        subquery.c.enriched_status != status.value,
                        and_(
                            subquery.c.enriched_status.is_(None),
                            subquery.c.status != status.value,
                        ),
                    )
                )
            )
        ).scalar()
        return not not_in_status_exists


def is_all_alerts_resolved(
    fingerprints: Optional[List[str]] = None,
    incident: Optional[Incident] = None,
    session: Optional[Session] = None,
):
    return is_all_alerts_in_status(
        fingerprints, incident, AlertStatus.RESOLVED, session
    )


def is_edge_incident_alert_resolved(
    incident: Incident, direction: Callable, session: Optional[Session] = None
) -> bool:
    if incident.alerts_count == 0:
        return False
    with existed_or_new_session(session) as session:
        enriched_status_field = get_json_extract_field(
            session, AlertEnrichment.enrichments, "status"
        )
        status_field = get_json_extract_field(session, Alert.event, "status")
        finerprint, enriched_status, status = session.exec(
            select(Alert.fingerprint, enriched_status_field, status_field)
            .select_from(Alert)
            .outerjoin(
                AlertEnrichment,
                and_(
                    Alert.tenant_id == AlertEnrichment.tenant_id,
                    Alert.fingerprint == AlertEnrichment.alert_fingerprint,
                ),
            )
            .join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == Alert.tenant_id,
                    LastAlertToIncident.fingerprint == Alert.fingerprint,
                ),
            )
            .where(LastAlertToIncident.incident_id == incident.id)
            .group_by(Alert.fingerprint)
            .having(func.max(Alert.timestamp))
            .order_by(direction(Alert.timestamp))
        ).first()
        return enriched_status == AlertStatus.RESOLVED.value or (
            enriched_status is None and status == AlertStatus.RESOLVED.value
        )


def is_first_incident_alert_resolved(
    incident: Incident, session: Optional[Session] = None
) -> bool:
    return is_edge_incident_alert_resolved(incident, func.min, session)


def is_last_incident_alert_resolved(
    incident: Incident, session: Optional[Session] = None
) -> bool:
    return is_edge_incident_alert_resolved(incident, func.max, session)


def query_alerts(
    tenant_id,
    provider_id=None,
    limit=1000,
    timeframe=None,
    upper_timestamp=None,
    lower_timestamp=None,
    skip_alerts_with_null_timestamp=True,
    sort_ascending=False,
) -> list[Alert]:
    """
    Get all alerts for a given tenant_id.
    Args:
        tenant_id (_type_): The tenant_id to filter the alerts by.
        provider_id (_type_, optional): The provider id to filter by. Defaults to None.
        limit (_type_, optional): The maximum number of alerts to return. Defaults to 1000.
        timeframe (_type_, optional): The number of days to look back for alerts. Defaults to None.
        upper_timestamp (_type_, optional): The upper timestamp to filter by. Defaults to None.
        lower_timestamp (_type_, optional): The lower timestamp to filter by. Defaults to None.
    Returns:
        List[Alert]: A list of Alert objects."""
    with Session(engine) as session:
        # Create the query
        query = session.query(Alert)
        # Apply subqueryload to force-load the alert_enrichment relationship
        query = query.options(subqueryload(Alert.alert_enrichment))
        # Filter by tenant_id
        query = query.filter(Alert.tenant_id == tenant_id)
        # if timeframe is provided, filter the alerts by the timeframe
        if timeframe:
            query = query.filter(
                Alert.timestamp
                >= datetime.now(tz=timezone.utc) - timedelta(days=timeframe)
            )
        filter_conditions = []
        if upper_timestamp is not None:
            filter_conditions.append(Alert.timestamp < upper_timestamp)
        if lower_timestamp is not None:
            filter_conditions.append(Alert.timestamp >= lower_timestamp)
        # Apply the filter conditions
        if filter_conditions:
            query = query.filter(*filter_conditions)  # Unpack and apply all conditions
        if provider_id:
            query = query.filter(Alert.provider_id == provider_id)
        if skip_alerts_with_null_timestamp:
            query = query.filter(Alert.timestamp.isnot(None))
        if sort_ascending:
            query = query.order_by(Alert.timestamp.asc())
        else:
            query = query.order_by(Alert.timestamp.desc())
        if limit:
            query = query.limit(limit)
        # Execute the query
        alerts = query.all()
    return alerts


def remove_alerts_to_incident_by_incident_id(
    tenant_id: str, incident_id: str | UUID, fingerprints: List[str]
) -> Optional[int]:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with Session(engine) as session:
        incident = session.exec(
            select(Incident).where(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
            )
        ).first()
        if not incident:
            return None
        # Removing alerts-to-incident relation for provided alerts_ids
        deleted = (
            session.query(LastAlertToIncident)
            .where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident.id,
                col(LastAlertToIncident.fingerprint).in_(fingerprints),
            )
            .update(
                {
                    "deleted_at": datetime.now(datetime.now().astimezone().tzinfo),
                }
            )
        )
        session.commit()
        # Getting aggregated data for incidents for alerts which just was removed
        alerts_data_for_incident = get_alerts_data_for_incident(
            tenant_id, fingerprints, session=session
        )
        service_field = get_json_extract_field(session, Alert.event, "service")
        # checking if services of removed alerts are still presented in alerts
        # which still assigned with the incident
        existed_services_query = (
            select(func.distinct(service_field))
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident_id,
                service_field.in_(alerts_data_for_incident["services"]),
            )
        )
        services_existed = session.exec(existed_services_query)
        # checking if sources (providers) of removed alerts are still presented in alerts
        # which still assigned with the incident
        existed_sources_query = (
            select(col(Alert.provider_type).distinct())
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident_id,
                col(Alert.provider_type).in_(alerts_data_for_incident["sources"]),
            )
        )
        sources_existed = session.exec(existed_sources_query)
        severity_field = get_json_extract_field(session, Alert.event, "severity")
        # checking if severities of removed alerts are still presented in alerts
        # which still assigned with the incident
        updated_severities_query = (
            select(severity_field)
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident_id,
            )
        )
        updated_severities_result = session.exec(updated_severities_query)
        updated_severities = [
            get_int_severity(severity) for severity in updated_severities_result
        ]
        # Making lists of services and sources to remove from the incident
        services_to_remove = [
            service
            for service in alerts_data_for_incident["services"]
            if service not in services_existed
        ]
        sources_to_remove = [
            source
            for source in alerts_data_for_incident["sources"]
            if source not in sources_existed
        ]
        last_received_field = get_json_extract_field(
            session, Alert.event, "lastReceived"
        )
        started_at, last_seen_at = session.exec(
            select(func.min(last_received_field), func.max(last_received_field))
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident.id,
            )
        ).one()
        # filtering removed entities from affected services and sources in the incident
        new_affected_services = [
            service
            for service in incident.affected_services
            if service not in services_to_remove
        ]
        new_sources = [
            source for source in incident.sources if source not in sources_to_remove
        ]
        if not incident.forced_severity:
            new_severity = (
                max(updated_severities)
                if updated_severities
                else IncidentSeverity.LOW.order
            )
        else:
            new_severity = incident.severity
        if isinstance(started_at, str):
            started_at = parse(started_at)
        if isinstance(last_seen_at, str):
            last_seen_at = parse(last_seen_at)
        alerts_count = (
            select(count(LastAlertToIncident.fingerprint)).where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident.id,
            )
        ).subquery()
        session.exec(
            update(Incident)
            .where(
                Incident.id == incident_id,
                Incident.tenant_id == tenant_id,
            )
            .values(
                alerts_count=alerts_count,
                last_seen_time=last_seen_at,
                start_time=started_at,
                affected_services=new_affected_services,
                severity=new_severity,
                sources=new_sources,
            )
        )
        session.commit()
        session.add(incident)
        session.refresh(incident)
        return deleted


def set_last_alert(
    tenant_id: str, alert: Alert, session: Optional[Session] = None, max_retries=3
) -> None:
    fingerprint = alert.fingerprint
    logger.info(f"Setting last alert for `{fingerprint}`")
    with existed_or_new_session(session) as session:
        for attempt in range(max_retries):
            logger.info(
                f"Attempt {attempt} to set last alert for `{fingerprint}`",
                extra={
                    "alert_id": alert.id,
                    "tenant_id": tenant_id,
                    "fingerprint": fingerprint,
                },
            )
            try:
                last_alert = get_last_alert_by_fingerprint(
                    tenant_id, fingerprint, session, for_update=True
                )
                # To prevent rare, but possible race condition
                # For example if older alert failed to process
                # and retried after new one
                if last_alert and last_alert.timestamp.replace(
                    tzinfo=tz.UTC
                ) < alert.timestamp.replace(tzinfo=tz.UTC):
                    logger.info(
                        f"Update last alert for `{fingerprint}`: {last_alert.alert_id} -> {alert.id}",
                        extra={
                            "alert_id": alert.id,
                            "tenant_id": tenant_id,
                            "fingerprint": fingerprint,
                        },
                    )
                    last_alert.timestamp = alert.timestamp
                    last_alert.alert_id = alert.id
                    last_alert.alert_hash = alert.alert_hash
                    session.add(last_alert)
                elif not last_alert:
                    logger.info(f"No last alert for `{fingerprint}`, creating new")
                    last_alert = LastAlert(
                        tenant_id=tenant_id,
                        fingerprint=alert.fingerprint,
                        timestamp=alert.timestamp,
                        first_timestamp=alert.timestamp,
                        alert_id=alert.id,
                        alert_hash=alert.alert_hash,
                    )
                session.add(last_alert)
                session.commit()
                break
            except OperationalError as ex:
                if "no such savepoint" in ex.args[0]:
                    logger.info(
                        f"No such savepoint while updating lastalert for `{fingerprint}`, retry #{attempt}"
                    )
                    session.rollback()
                    if attempt >= max_retries:
                        raise ex
                    continue
                if "Deadlock found" in ex.args[0]:
                    logger.info(
                        f"Deadlock found while updating lastalert for `{fingerprint}`, retry #{attempt}"
                    )
                    session.rollback()
                    if attempt >= max_retries:
                        raise ex
                    continue
            except NoActiveSqlTransaction:
                logger.exception(
                    f"No active sql transaction while updating lastalert for `{fingerprint}`, retry #{attempt}",
                    extra={
                        "alert_id": alert.id,
                        "tenant_id": tenant_id,
                        "fingerprint": fingerprint,
                    },
                )
                continue
            logger.debug(
                f"Successfully updated lastalert for `{fingerprint}`",
                extra={
                    "alert_id": alert.id,
                    "tenant_id": tenant_id,
                    "fingerprint": fingerprint,
                },
            )
            # break the retry loop
            break
