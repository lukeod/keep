"""Database operations for incident."""

import json

from datetime import datetime as dt, timedelta, timezone
from typing import List, Tuple, Optional
from uuid import UUID
from enum import Enum

from sqlalchemy import String, and_, cast, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import foreign, joinedload
from sqlalchemy.sql import expression
from sqlmodel import Session, col, select

from keep.api.core.db._common import (
    ALLOWED_INCIDENT_FILTERS,
    Session,
    engine,
    logger,
    retry_on_db_error,
    existed_or_new_session,
    NULL_FOR_DELETED_AT,
    filter_query,
    __convert_to_uuid,
)
from keep.api.core.db.alert import (
    enrich_incidents_with_alerts,
    add_alerts_to_incident,
    remove_alerts_to_incident_by_incident_id,
)
from keep.api.models.db.alert import Alert, AlertEnrichment, LastAlertToIncident
from keep.api.models.db.incident import *
from keep.api.models.db.rule import Rule
from keep.api.models.incident import IncidentDto, IncidentDtoIn, IncidentSorting
from keep.api.models.time_stamp import TimeStampFilter


class DestinationIncidentNotFound(Exception):
    pass


def apply_incident_filters(session: Session, filters: dict, query):
    for field_name, value in filters.items():
        if field_name in ALLOWED_INCIDENT_FILTERS:
            if field_name in ["affected_services", "sources"]:
                field = getattr(Incident, field_name)
                # Rare case with empty values
                if isinstance(value, list) and not any(value):
                    continue
                query = filter_query(session, query, field, value)
            else:
                field = getattr(Incident, field_name)
                if isinstance(value, list):
                    query = query.filter(col(field).in_(value))
                else:
                    query = query.filter(col(field) == value)
    return query


def assign_alert_to_incident(
    fingerprint: str,
    incident: Incident,
    tenant_id: str,
    session: Optional[Session] = None,
):
    return add_alerts_to_incident(tenant_id, incident, [fingerprint], session=session)


def calc_incidents_mttr(tenant_id: str, timestamp_filter: TimeStampFilter = None):
    """
    Calculate the Mean Time to Resolve (MTTR) for incidents over time for a specific tenant.
    Args:
        tenant_id (str): ID of the tenant whose incidents are being analyzed.
        timestamp_filter (TimeStampFilter, optional): Filter to specify the time range.
            - lower_timestamp (datetime): Start of the time range.
            - upper_timestamp (datetime): End of the time range.
    Returns:
        List[dict]: A list of dictionaries representing the hourly MTTR of incidents.
            Each dictionary contains:
            - 'timestamp' (str): Timestamp of the hour in "YYYY-MM-DD HH:00" format.
            - 'mttr' (float): Mean Time to Resolve incidents in that hour (in hours).
    Notes:
        - If no timestamp_filter is provided, defaults to the last 24 hours.
        - Only includes resolved incidents.
        - Supports MySQL, PostgreSQL, and SQLite for timestamp formatting.
    """
    with Session(engine) as session:
        twenty_four_hours_ago = dt.now(tz=timezone.utc) - timedelta(hours=24)
        time_format = "%Y-%m-%d %H"
        filters = [
            Incident.tenant_id == tenant_id,
            Incident.status == IncidentStatus.RESOLVED.value,
        ]
        if timestamp_filter:
            if timestamp_filter.lower_timestamp:
                filters.append(
                    Incident.creation_time >= timestamp_filter.lower_timestamp
                )
            if timestamp_filter.upper_timestamp:
                filters.append(
                    Incident.creation_time <= timestamp_filter.upper_timestamp
                )
        else:
            filters.append(Incident.creation_time >= twenty_four_hours_ago)
        # Database-specific timestamp formatting
        if session.bind.dialect.name == "mysql":
            timestamp_format = func.date_format(Incident.creation_time, time_format)
        elif session.bind.dialect.name == "postgresql":
            timestamp_format = func.to_char(Incident.creation_time, "YYYY-MM-DD HH")
        elif session.bind.dialect.name == "sqlite":
            timestamp_format = func.strftime(time_format, Incident.creation_time)
        query = (
            session.query(
                timestamp_format.label("time"),
                Incident.start_time,
                Incident.end_time,
                func.count().label("incidents"),
            )
            .filter(*filters)
            .group_by("time", Incident.start_time, Incident.end_time)
            .order_by("time")
        )
        results = {}
        for time, start_time, end_time, incidents in query.all():
            if start_time and end_time:
                resolution_time = (
                    end_time - start_time
                ).total_seconds() / 3600  # in hours
                time_str = str(time)
                if time_str not in results:
                    results[time_str] = {"number": 0, "mttr": 0}
                results[time_str]["number"] += incidents
                results[time_str]["mttr"] += resolution_time * incidents
        distribution = []
        current_time = timestamp_filter.lower_timestamp.replace(
            minute=0, second=0, microsecond=0
        )
        while current_time <= timestamp_filter.upper_timestamp:
            timestamp_str = current_time.strftime(time_format)
            if timestamp_str in results and results[timestamp_str]["number"] > 0:
                avg_mttr = (
                    results[timestamp_str]["mttr"] / results[timestamp_str]["number"]
                )
            else:
                avg_mttr = 0
            distribution.append(
                {
                    "timestamp": timestamp_str + ":00",
                    "mttr": avg_mttr,
                }
            )
            current_time += timedelta(hours=1)
        return distribution


def change_incident_status_by_id(
    tenant_id: str,
    incident_id: UUID | str,
    status: IncidentStatus,
    end_time: dt | None = None,
) -> bool:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with Session(engine) as session:
        stmt = (
            update(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
            )
            .values(
                status=status.value,
                end_time=end_time,
            )
        )
        session.exec(stmt)
        session.commit()


def confirm_predicted_incident_by_id(
    tenant_id: str,
    incident_id: UUID | str,
):
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with Session(engine) as session:
        incident = session.exec(
            select(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
                Incident.is_candidate == expression.true(),
            )
            .options(joinedload(Incident.alerts))
        ).first()
        if not incident:
            return None
        session.query(Incident).filter(
            Incident.tenant_id == tenant_id,
            Incident.id == incident_id,
            Incident.is_candidate == expression.true(),
        ).update(
            {
                "is_visible": True,
            }
        )
        session.commit()
        session.refresh(incident)
        return incident


@retry_on_db_error
def create_incident_for_grouping_rule(
    tenant_id,
    rule: Rule,
    rule_fingerprint,
    incident_name: str = None,
    past_incident: Optional[Incident] = None,
    session: Optional[Session] = None,
):
    with existed_or_new_session(session) as session:
        # Create and add a new incident if it doesn't exist
        incident = Incident(
            tenant_id=tenant_id,
            user_generated_name=incident_name or f"{rule.name}",
            rule_id=rule.id,
            rule_fingerprint=rule_fingerprint,
            is_predicted=True,
            is_candidate=rule.require_approve,
            is_visible=False,  # rule.create_on == CreateIncidentOn.ANY.value,
            incident_type=IncidentType.RULE.value,
            same_incident_in_the_past_id=past_incident.id if past_incident else None,
            resolve_on=rule.resolve_on,
        )
        session.add(incident)
        session.flush()
        if rule.incident_prefix:
            incident.user_generated_name = f"{rule.incident_prefix}-{incident.running_number} - {incident.user_generated_name}"
        session.commit()
        session.refresh(incident)
    return incident


@retry_on_db_error
def create_incident_for_topology(
    tenant_id: str, alert_group: list[Alert], session: Session
) -> Incident:
    """Create a new incident from topology-connected alerts"""
    # Get highest severity from alerts
    severity = max(alert.severity for alert in alert_group)
    # Get all services
    services = set()
    service_names = set()
    for alert in alert_group:
        services.update(alert.service_ids)
        service_names.update(alert.service_names)
    incident = Incident(
        tenant_id=tenant_id,
        user_generated_name=f"Topology incident: Multiple alerts across {', '.join(service_names)}",
        severity=severity.value,
        status=IncidentStatus.FIRING.value,
        is_visible=True,
        incident_type=IncidentType.TOPOLOGY.value,  # Set incident type for topology
        data={"services": list(services), "alert_count": len(alert_group)},
    )
    return incident


@retry_on_db_error
def create_incident_from_dict(
    tenant_id: str, incident_data: dict, session: Optional[Session] = None
) -> Optional[Incident]:
    is_predicted = incident_data.get("is_predicted", False)
    if "is_candidate" not in incident_data:
        incident_data["is_candidate"] = is_predicted
    with existed_or_new_session(session) as session:
        new_incident = Incident(**incident_data, tenant_id=tenant_id)
        session.add(new_incident)
        session.commit()
        session.refresh(new_incident)
    return new_incident


def create_incident_from_dto(
    tenant_id: str,
    incident_dto: IncidentDtoIn | IncidentDto,
    generated_from_ai: bool = False,
    session: Optional[Session] = None,
) -> Optional[Incident]:
    """
    Creates an incident for a specified tenant based on the provided incident data transfer object (DTO).
    Args:
        tenant_id (str): The unique identifier of the tenant for whom the incident is being created.
        incident_dto (IncidentDtoIn | IncidentDto): The data transfer object containing incident details.
            Can be an instance of `IncidentDtoIn` or `IncidentDto`.
        generated_from_ai (bool, optional): Specifies whether the incident was generated by Keep's AI. Defaults to False.
    Returns:
        Optional[Incident]: The newly created `Incident` object if successful, otherwise `None`.
    """
    if issubclass(type(incident_dto), IncidentDto) and generated_from_ai:
        # NOTE: we do not use dto's alerts, alert count, start time etc
        #       because we want to re-use the BL of creating incidents
        #       where all of these are calculated inside add_alerts_to_incident
        incident_dict = {
            "user_summary": incident_dto.user_summary,
            "generated_summary": incident_dto.description,
            "user_generated_name": incident_dto.user_generated_name,
            "ai_generated_name": incident_dto.dict().get("name"),
            "assignee": incident_dto.assignee,
            "is_predicted": False,  # its not a prediction, but an AI generation
            "is_candidate": False,  # confirmed by the user :)
            "is_visible": True,  # confirmed by the user :)
            "incident_type": IncidentType.AI.value,
        }
    elif issubclass(type(incident_dto), IncidentDto):
        # we will reach this block when incident is pulled from a provider
        incident_dict = incident_dto.to_db_incident().dict()
        if "incident_type" not in incident_dict:
            incident_dict["incident_type"] = IncidentType.MANUAL.value
    else:
        # We'll reach this block when a user creates an incident
        incident_dict = incident_dto.dict()
        # Keep existing incident_type if present, default to MANUAL if not
        if "incident_type" not in incident_dict:
            incident_dict["incident_type"] = IncidentType.MANUAL.value
    if incident_dto.severity is not None:
        incident_dict["severity"] = incident_dto.severity.order
    return create_incident_from_dict(tenant_id, incident_dict, session)


def delete_incident_by_id(
    tenant_id: str, incident_id: UUID, session: Optional[Session] = None
) -> bool:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with existed_or_new_session(session) as session:
        incident = session.exec(
            select(Incident).filter(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
            )
        ).first()
        session.execute(
            update(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.id == incident.id,
            )
            .values({"status": IncidentStatus.DELETED.value})
        )
        session.commit()
        return True


def enrich_incidents_with_enrichments(
    tenant_id: str,
    incidents: List[Incident],
    session: Optional[Session] = None,
) -> List[Incident]:
    """Enrich incidents with their enrichment data."""
    if not incidents:
        return incidents
    with existed_or_new_session(session) as session:
        # Get all enrichments for these incidents in one query
        enrichments = session.exec(
            select(AlertEnrichment).where(
                AlertEnrichment.tenant_id == tenant_id,
                AlertEnrichment.alert_fingerprint.in_(
                    [str(incident.id) for incident in incidents]
                ),
            )
        ).all()
        # Create a mapping of incident_id to enrichment
        enrichments_map = {
            enrichment.alert_fingerprint: enrichment.enrichments
            for enrichment in enrichments
        }
        # Add enrichments to each incident
        for incident in incidents:
            incident._enrichments = enrichments_map.get(str(incident.id), {})
        return incidents


def get_future_incidents_by_incident_id(
    incident_id: str,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> tuple[List[Incident], int]:
    with Session(engine) as session:
        query = session.query(
            Incident,
        ).filter(Incident.same_incident_in_the_past_id == incident_id)
        if limit:
            query = query.limit(limit)
        if offset:
            query = query.offset(offset)
    total_count = query.count()
    return query.all(), total_count


def get_incident_by_fingerprint(
    tenant_id: str, fingerprint: str, session: Optional[Session] = None
) -> Optional[Incident]:
    with existed_or_new_session(session) as session:
        return session.exec(
            select(Incident).where(
                Incident.tenant_id == tenant_id, Incident.fingerprint == fingerprint
            )
        ).one_or_none()


def get_incident_by_id(
    tenant_id: str,
    incident_id: str | UUID,
    with_alerts: bool = False,
    session: Optional[Session] = None,
) -> Optional[Incident]:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id, should_raise=True)
    with existed_or_new_session(session) as session:
        query = (
            session.query(
                Incident,
                AlertEnrichment,
            )
            .outerjoin(
                AlertEnrichment,
                and_(
                    Incident.tenant_id == AlertEnrichment.tenant_id,
                    cast(col(Incident.id), String)
                    == foreign(AlertEnrichment.alert_fingerprint),
                ),
            )
            .filter(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
            )
        )
        incident_with_enrichments = query.first()
        if incident_with_enrichments:
            incident, enrichments = incident_with_enrichments
            if with_alerts:
                enrich_incidents_with_alerts(
                    tenant_id,
                    [incident],
                    session,
                )
            if enrichments:
                incident.set_enrichments(enrichments.enrichments)
        else:
            incident = None
    return incident


def get_incident_for_grouping_rule(
    tenant_id, rule, rule_fingerprint, session: Optional[Session] = None
) -> Tuple[Optional[Incident], bool]:
    # checks if incident with the incident criteria exists, if not it creates it
    #   and then assign the alert to the incident
    with existed_or_new_session(session) as session:
        incident = session.exec(
            select(Incident)
            .where(Incident.tenant_id == tenant_id)
            .where(Incident.rule_id == rule.id)
            .where(Incident.rule_fingerprint == rule_fingerprint)
            .order_by(Incident.creation_time.desc())
        ).first()
        # if the last alert in the incident is older than the timeframe, create a new incident
        is_incident_expired = False
        if incident and incident.status in [
            IncidentStatus.RESOLVED.value,
            IncidentStatus.MERGED.value,
            IncidentStatus.DELETED.value,
        ]:
            is_incident_expired = True
        elif incident and incident.alerts_count > 0:
            enrich_incidents_with_alerts(tenant_id, [incident], session)
            is_incident_expired = max(
                alert.timestamp for alert in incident.alerts
            ) < dt.now(tz=timezone.utc) - timedelta(seconds=rule.timeframe)
        # if there is no incident with the rule_fingerprint, create it or existed is already expired
        if not incident:
            return None, None
    return incident, is_incident_expired


def get_incident_unique_fingerprint_count(
    tenant_id: str, incident_id: str | UUID
) -> int:
    with Session(engine) as session:
        return session.execute(
            select(func.count(1))
            .select_from(LastAlertToIncident)
            .where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident_id,
            )
        ).scalar()


def get_incidents_count(
    tenant_id: str,
) -> int:
    with Session(engine) as session:
        return (
            session.query(Incident)
            .filter(
                Incident.tenant_id == tenant_id,
            )
            .count()
        )


def get_incidents_created_distribution(
    tenant_id: str, timestamp_filter: TimeStampFilter = None
):
    """
    Calculate the distribution of incidents created over time for a specific tenant.
    Args:
        tenant_id (str): ID of the tenant whose incidents are being queried.
        timestamp_filter (TimeStampFilter, optional): Filter to specify the time range.
            - lower_timestamp (datetime): Start of the time range.
            - upper_timestamp (datetime): End of the time range.
    Returns:
        List[dict]: A list of dictionaries representing the hourly distribution of incidents.
            Each dictionary contains:
            - 'timestamp' (str): Timestamp of the hour in "YYYY-MM-DD HH:00" format.
            - 'number' (int): Number of incidents created in that hour.
    Notes:
        - If no timestamp_filter is provided, defaults to the last 24 hours.
        - Supports MySQL, PostgreSQL, and SQLite for timestamp formatting.
    """
    with Session(engine) as session:
        twenty_four_hours_ago = dt.now(tz=timezone.utc) - timedelta(hours=24)
        time_format = "%Y-%m-%d %H"
        filters = [Incident.tenant_id == tenant_id]
        if timestamp_filter:
            if timestamp_filter.lower_timestamp:
                filters.append(
                    Incident.creation_time >= timestamp_filter.lower_timestamp
                )
            if timestamp_filter.upper_timestamp:
                filters.append(
                    Incident.creation_time <= timestamp_filter.upper_timestamp
                )
        else:
            filters.append(Incident.creation_time >= twenty_four_hours_ago)
        # Database-specific timestamp formatting
        if session.bind.dialect.name == "mysql":
            timestamp_format = func.date_format(Incident.creation_time, time_format)
        elif session.bind.dialect.name == "postgresql":
            timestamp_format = func.to_char(Incident.creation_time, "YYYY-MM-DD HH")
        elif session.bind.dialect.name == "sqlite":
            timestamp_format = func.strftime(time_format, Incident.creation_time)
        query = (
            session.query(
                timestamp_format.label("time"), func.count().label("incidents")
            )
            .filter(*filters)
            .group_by("time")
            .order_by("time")
        )
        results = {str(time): incidents for time, incidents in query.all()}
        distribution = []
        current_time = timestamp_filter.lower_timestamp.replace(
            minute=0, second=0, microsecond=0
        )
        while current_time <= timestamp_filter.upper_timestamp:
            timestamp_str = current_time.strftime(time_format)
            distribution.append(
                {
                    "timestamp": timestamp_str + ":00",
                    "number": results.get(timestamp_str, 0),
                }
            )
            current_time += timedelta(hours=1)
        return distribution


def get_incidents_meta_for_tenant(tenant_id: str) -> dict:
    with Session(engine) as session:
        if session.bind.dialect.name == "sqlite":
            sources_join = func.json_each(Incident.sources).table_valued("value")
            affected_services_join = func.json_each(
                Incident.affected_services
            ).table_valued("value")
            query = (
                select(
                    func.json_group_array(col(Incident.assignee).distinct()).label(
                        "assignees"
                    ),
                    func.json_group_array(sources_join.c.value.distinct()).label(
                        "sources"
                    ),
                    func.json_group_array(
                        affected_services_join.c.value.distinct()
                    ).label("affected_services"),
                )
                .select_from(Incident)
                .outerjoin(sources_join, sources_join.c.value.isnot(None))
                .outerjoin(
                    affected_services_join, affected_services_join.c.value.isnot(None)
                )
                .filter(Incident.tenant_id == tenant_id, Incident.is_visible == True)
            )
            results = session.exec(query).one_or_none()
            if not results:
                return {}
            return {
                "assignees": list(filter(bool, json.loads(results.assignees))),
                "sources": list(filter(bool, json.loads(results.sources))),
                "services": list(filter(bool, json.loads(results.affected_services))),
            }
        elif session.bind.dialect.name == "mysql":
            sources_join = func.json_table(
                Incident.sources, Column("value", String(127))
            ).table_valued("value")
            affected_services_join = func.json_table(
                Incident.affected_services, Column("value", String(127))
            ).table_valued("value")
            query = (
                select(
                    func.group_concat(col(Incident.assignee).distinct()).label(
                        "assignees"
                    ),
                    func.group_concat(sources_join.c.value.distinct()).label("sources"),
                    func.group_concat(affected_services_join.c.value.distinct()).label(
                        "affected_services"
                    ),
                )
                .select_from(Incident)
                .outerjoin(sources_join, sources_join.c.value.isnot(None))
                .outerjoin(
                    affected_services_join, affected_services_join.c.value.isnot(None)
                )
                .filter(Incident.tenant_id == tenant_id, Incident.is_visible == True)
            )
            results = session.exec(query).one_or_none()
            if not results:
                return {}
            return {
                "assignees": results.assignees.split(",") if results.assignees else [],
                "sources": results.sources.split(",") if results.sources else [],
                "services": (
                    results.affected_services.split(",")
                    if results.affected_services
                    else []
                ),
            }
        elif session.bind.dialect.name == "postgresql":
            sources_join = func.json_array_elements_text(Incident.sources).table_valued(
                "value"
            )
            affected_services_join = func.json_array_elements_text(
                Incident.affected_services
            ).table_valued("value")
            query = (
                select(
                    func.json_agg(col(Incident.assignee).distinct()).label("assignees"),
                    func.json_agg(sources_join.c.value.distinct()).label("sources"),
                    func.json_agg(affected_services_join.c.value.distinct()).label(
                        "affected_services"
                    ),
                )
                .select_from(Incident)
                .outerjoin(sources_join, sources_join.c.value.isnot(None))
                .outerjoin(
                    affected_services_join, affected_services_join.c.value.isnot(None)
                )
                .filter(Incident.tenant_id == tenant_id, Incident.is_visible == True)
            )
            results = session.exec(query).one_or_none()
            if not results:
                return {}
            assignees, sources, affected_services = results
            return {
                "assignees": list(filter(bool, assignees)) if assignees else [],
                "sources": list(filter(bool, sources)) if sources else [],
                "services": (
                    list(filter(bool, affected_services)) if affected_services else []
                ),
            }
        return {}


def get_last_incidents(
    tenant_id: str,
    limit: int = 25,
    offset: int = 0,
    timeframe: int = None,
    upper_timestamp: dt = None,
    lower_timestamp: dt = None,
    is_candidate: bool = False,
    sorting: Optional[IncidentSorting] = IncidentSorting.creation_time,
    with_alerts: bool = False,
    is_predicted: bool = None,
    filters: Optional[dict] = None,
    allowed_incident_ids: Optional[List[str]] = None,
) -> Tuple[list[Incident], int]:
    """
    Get the last incidents and total amount of incidents.
    Args:
        tenant_id (str): The tenant_id to filter the incidents by.
        limit (int): Amount of objects to return
        offset (int): Current offset for
        timeframe (int|null): Return incidents only for the last <N> days
        upper_timestamp: datetime = None,
        lower_timestamp: datetime = None,
        is_candidate (bool): filter incident candidates or real incidents
        sorting: Optional[IncidentSorting]: how to sort the data
        with_alerts (bool): Pre-load alerts or not
        is_predicted (bool): filter only incidents predicted by KeepAI
        filters (dict): dict of filters
    Returns:
        List[Incident]: A list of Incident objects.
    """
    with Session(engine) as session:
        query = session.query(
            Incident,
        ).filter(
            Incident.tenant_id == tenant_id,
            Incident.is_candidate == is_candidate,
            Incident.is_visible == True,
        )
        if allowed_incident_ids:
            query = query.filter(Incident.id.in_(allowed_incident_ids))
        if is_predicted is not None:
            query = query.filter(Incident.is_predicted == is_predicted)
        if timeframe:
            query = query.filter(
                Incident.start_time
                >= dt.now(tz=timezone.utc) - timedelta(days=timeframe)
            )
        if upper_timestamp and lower_timestamp:
            query = query.filter(
                col(Incident.last_seen_time).between(lower_timestamp, upper_timestamp)
            )
        elif upper_timestamp:
            query = query.filter(Incident.last_seen_time <= upper_timestamp)
        elif lower_timestamp:
            query = query.filter(Incident.last_seen_time >= lower_timestamp)
        if filters:
            query = apply_incident_filters(session, filters, query)
        if sorting:
            query = query.order_by(sorting.get_order_by(Incident))
        total_count = query.count()
        # Order by start_time in descending order and limit the results
        query = query.limit(limit).offset(offset)
        # Execute the query
        incidents = query.all()
        if with_alerts:
            enrich_incidents_with_alerts(tenant_id, incidents, session)
        enrich_incidents_with_enrichments(tenant_id, incidents, session)
    return incidents, total_count


def get_rule_incidents_count_db(tenant_id):
    with Session(engine) as session:
        query = (
            session.query(Incident.rule_id, func.count(Incident.id))
            .select_from(Incident)
            .filter(Incident.tenant_id == tenant_id, col(Incident.rule_id).isnot(None))
            .group_by(Incident.rule_id)
        )
        return dict(query.all())


def merge_incidents_to_id(
    tenant_id: str,
    source_incident_ids: List[UUID],
    # Maybe to add optional destionation_incident_dto to merge to
    destination_incident_id: UUID,
    merged_by: str | None = None,
) -> Tuple[List[UUID], List[UUID], List[UUID]]:
    with Session(engine) as session:
        destination_incident = session.exec(
            select(Incident).where(
                Incident.tenant_id == tenant_id, Incident.id == destination_incident_id
            )
        ).first()
        if not destination_incident:
            raise DestinationIncidentNotFound(
                f"Destination incident with id {destination_incident_id} not found"
            )
        source_incidents = session.exec(
            select(Incident).filter(
                Incident.tenant_id == tenant_id,
                Incident.id.in_(source_incident_ids),
            )
        ).all()
        enrich_incidents_with_alerts(tenant_id, source_incidents, session=session)
        merged_incident_ids = []
        failed_incident_ids = []
        for source_incident in source_incidents:
            source_incident_alerts_fingerprints = [
                alert.fingerprint for alert in source_incident.alerts
            ]
            source_incident.merged_into_incident_id = destination_incident.id
            source_incident.merged_at = dt.now(tz=timezone.utc)
            source_incident.status = IncidentStatus.MERGED.value
            source_incident.merged_by = merged_by
            try:
                remove_alerts_to_incident_by_incident_id(
                    tenant_id,
                    source_incident.id,
                    [alert.fingerprint for alert in source_incident.alerts],
                )
            except OperationalError as e:
                logger.error(
                    f"Error removing alerts from incident {source_incident.id}: {e}"
                )
            try:
                add_alerts_to_incident(
                    tenant_id,
                    destination_incident,
                    source_incident_alerts_fingerprints,
                    session=session,
                )
                merged_incident_ids.append(source_incident.id)
            except OperationalError as e:
                logger.error(
                    f"Error adding alerts to incident {destination_incident.id} from {source_incident.id}: {e}"
                )
                failed_incident_ids.append(source_incident.id)
        session.commit()
        session.refresh(destination_incident)
        return merged_incident_ids, failed_incident_ids


@retry_on_db_error
def update_incident_from_dto_by_id(
    tenant_id: str,
    incident_id: str | UUID,
    updated_incident_dto: IncidentDtoIn | IncidentDto,
    generated_by_ai: bool = False,
) -> Optional[Incident]:
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
        if issubclass(type(updated_incident_dto), IncidentDto):
            # We execute this when we update an incident received from the provider
            updated_data = updated_incident_dto.to_db_incident().model_dump()
        else:
            # When a user updates an Incident
            updated_data = updated_incident_dto.dict()
        for key, value in updated_data.items():
            # Update only if the new value is different from the current one
            if hasattr(incident, key) and getattr(incident, key) != value:
                if isinstance(value, Enum):
                    setattr(incident, key, value.value)
                else:
                    if value is not None:
                        setattr(incident, key, value)
        if "same_incident_in_the_past_id" in updated_data:
            incident.same_incident_in_the_past_id = updated_data[
                "same_incident_in_the_past_id"
            ]
        if generated_by_ai:
            incident.generated_summary = updated_incident_dto.user_summary
        else:
            incident.user_summary = updated_incident_dto.user_summary
        session.commit()
        session.refresh(incident)
        return incident


def update_incident_name(tenant_id: str, incident_id: UUID, name: str) -> Incident:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with Session(engine) as session:
        incident = session.exec(
            select(Incident)
            .where(Incident.tenant_id == tenant_id)
            .where(Incident.id == incident_id)
        ).first()
        if not incident:
            logger.error(
                f"Incident not found for tenant {tenant_id} and incident {incident_id}",
                extra={"tenant_id": tenant_id},
            )
            return
        incident.ai_generated_name = name
        session.commit()
        session.refresh(incident)
        return incident


def update_incident_severity(
    tenant_id: str, incident_id: UUID, severity: IncidentSeverity
) -> Optional[Incident]:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with Session(engine) as session:
        incident = session.exec(
            select(Incident)
            .where(Incident.tenant_id == tenant_id)
            .where(Incident.id == incident_id)
        ).first()
        if not incident:
            logger.error(
                f"Incident not found for tenant {tenant_id} and incident {incident_id}",
                extra={"tenant_id": tenant_id},
            )
            return
        incident.severity = severity.order
        incident.forced_severity = True
        session.add(incident)
        session.commit()
        session.refresh(incident)
        return incident


def update_incident_summary(
    tenant_id: str, incident_id: UUID, summary: str
) -> Incident:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with Session(engine) as session:
        incident = session.exec(
            select(Incident)
            .where(Incident.tenant_id == tenant_id)
            .where(Incident.id == incident_id)
        ).first()
        if not incident:
            logger.error(
                f"Incident not found for tenant {tenant_id} and incident {incident_id}",
                extra={"tenant_id": tenant_id},
            )
            return
        incident.generated_summary = summary
        session.commit()
        session.refresh(incident)
        return
