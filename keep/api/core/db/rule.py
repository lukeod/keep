"""Database operations for rule."""

from datetime import datetime as dt, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlmodel import Session, select

from keep.api.core.db._common import (
    Session,
    engine,
    logger,
    __convert_to_uuid,
    NULL_FOR_DELETED_AT,
    existed_or_new_session,
)
from keep.api.models.db.alert import (
    AlertDeduplicationEvent,
    AlertDeduplicationRule,
    LastAlertToIncident,
)
from keep.api.models.db.incident import Incident
from keep.api.models.db.mapping import MappingRule
from keep.api.models.db.rule import *
from keep.api.models.db.extraction import ExtractionRule


def create_deduplication_event(
    tenant_id, deduplication_rule_id, deduplication_type, provider_id, provider_type
):
    logger.debug(
        "Adding deduplication event",
        extra={
            "deduplication_rule_id": deduplication_rule_id,
            "deduplication_type": deduplication_type,
            "provider_id": provider_id,
            "provider_type": provider_type,
            "tenant_id": tenant_id,
        },
    )
    if isinstance(deduplication_rule_id, str):
        deduplication_rule_id = __convert_to_uuid(deduplication_rule_id)
        if not deduplication_rule_id:
            logger.debug(
                "Deduplication rule id is not a valid uuid",
                extra={
                    "deduplication_rule_id": deduplication_rule_id,
                    "tenant_id": tenant_id,
                },
            )
            return False
    with Session(engine) as session:
        deduplication_event = AlertDeduplicationEvent(
            tenant_id=tenant_id,
            deduplication_rule_id=deduplication_rule_id,
            deduplication_type=deduplication_type,
            provider_id=provider_id,
            provider_type=provider_type,
            timestamp=dt.now(tz=timezone.utc),
            date_hour=dt.now(tz=timezone.utc).replace(
                minute=0, second=0, microsecond=0
            ),
        )
        session.add(deduplication_event)
        session.commit()
        logger.debug(
            "Deduplication event added",
            extra={
                "deduplication_event_id": deduplication_event.id,
                "tenant_id": tenant_id,
            },
        )


def create_deduplication_rule(
    tenant_id: str,
    name: str,
    description: str,
    provider_id: str | None,
    provider_type: str,
    created_by: str,
    enabled: bool = True,
    fingerprint_fields: list[str] = [],
    full_deduplication: bool = False,
    ignore_fields: list[str] = [],
    priority: int = 0,
    is_provisioned: bool = False,
):
    with Session(engine) as session:
        new_rule = AlertDeduplicationRule(
            tenant_id=tenant_id,
            name=name,
            description=description,
            provider_id=provider_id,
            provider_type=provider_type,
            last_updated_by=created_by,  # on creation, last_updated_by is the same as created_by
            created_by=created_by,
            enabled=enabled,
            fingerprint_fields=fingerprint_fields,
            full_deduplication=full_deduplication,
            ignore_fields=ignore_fields,
            priority=priority,
            is_provisioned=is_provisioned,
        )
        session.add(new_rule)
        session.commit()
        session.refresh(new_rule)
    return new_rule


def create_rule(
    tenant_id,
    name,
    timeframe,
    timeunit,
    definition,
    definition_cel,
    created_by,
    grouping_criteria=None,
    group_description=None,
    require_approve=False,
    resolve_on=ResolveOn.NEVER.value,
    create_on=CreateIncidentOn.ANY.value,
    incident_name_template=None,
    incident_prefix=None,
    multi_level=False,
    multi_level_property_name=None,
    threshold=1,
):
    grouping_criteria = grouping_criteria or []
    with Session(engine) as session:
        rule = Rule(
            tenant_id=tenant_id,
            name=name,
            timeframe=timeframe,
            timeunit=timeunit,
            definition=definition,
            definition_cel=definition_cel,
            created_by=created_by,
            creation_time=dt.now(tz=timezone.utc),
            grouping_criteria=grouping_criteria,
            group_description=group_description,
            require_approve=require_approve,
            resolve_on=resolve_on,
            create_on=create_on,
            incident_name_template=incident_name_template,
            incident_prefix=incident_prefix,
            multi_level=multi_level,
            multi_level_property_name=multi_level_property_name,
            threshold=threshold,
        )
        session.add(rule)
        session.commit()
        session.refresh(rule)
        return rule


def delete_deduplication_rule(rule_id: str, tenant_id: str) -> bool:
    rule_uuid = __convert_to_uuid(rule_id)
    if not rule_uuid:
        return False
    with Session(engine) as session:
        rule = session.exec(
            select(AlertDeduplicationRule)
            .where(AlertDeduplicationRule.id == rule_uuid)
            .where(AlertDeduplicationRule.tenant_id == tenant_id)
        ).first()
        if not rule:
            return False
        session.delete(rule)
        session.commit()
    return True


def delete_rule(tenant_id, rule_id):
    with Session(engine) as session:
        rule_uuid = __convert_to_uuid(rule_id)
        if not rule_uuid:
            return False
        rule = session.exec(
            select(Rule).where(Rule.tenant_id == tenant_id).where(Rule.id == rule_uuid)
        ).first()
        if rule and not rule.is_deleted:
            rule.is_deleted = True
            session.commit()
            return True
        return False


def get_all_deduplication_rules(tenant_id):
    with Session(engine) as session:
        rules = session.exec(
            select(AlertDeduplicationRule).where(
                AlertDeduplicationRule.tenant_id == tenant_id
            )
        ).all()
    return rules


def get_all_deduplication_stats(tenant_id):
    with Session(engine) as session:
        # Query to get all-time deduplication stats
        all_time_query = (
            select(
                AlertDeduplicationEvent.deduplication_rule_id,
                AlertDeduplicationEvent.provider_id,
                AlertDeduplicationEvent.provider_type,
                AlertDeduplicationEvent.deduplication_type,
                func.count(AlertDeduplicationEvent.id).label("dedup_count"),
            )
            .where(AlertDeduplicationEvent.tenant_id == tenant_id)
            .group_by(
                AlertDeduplicationEvent.deduplication_rule_id,
                AlertDeduplicationEvent.provider_id,
                AlertDeduplicationEvent.provider_type,
                AlertDeduplicationEvent.deduplication_type,
            )
        )
        all_time_results = session.exec(all_time_query).all()
        # Query to get alerts distribution in the last 24 hours
        twenty_four_hours_ago = dt.now(tz=timezone.utc) - timedelta(hours=24)
        alerts_last_24_hours_query = (
            select(
                AlertDeduplicationEvent.deduplication_rule_id,
                AlertDeduplicationEvent.provider_id,
                AlertDeduplicationEvent.provider_type,
                AlertDeduplicationEvent.date_hour,
                func.count(AlertDeduplicationEvent.id).label("hourly_count"),
            )
            .where(AlertDeduplicationEvent.tenant_id == tenant_id)
            .where(AlertDeduplicationEvent.date_hour >= twenty_four_hours_ago)
            .group_by(
                AlertDeduplicationEvent.deduplication_rule_id,
                AlertDeduplicationEvent.provider_id,
                AlertDeduplicationEvent.provider_type,
                AlertDeduplicationEvent.date_hour,
            )
        )
        alerts_last_24_hours_results = session.exec(alerts_last_24_hours_query).all()
        # Create a dictionary with deduplication stats for each rule
        stats = {}
        current_hour = dt.now(tz=timezone.utc).replace(
            minute=0, second=0, microsecond=0
        )
        for result in all_time_results:
            provider_id = result.provider_id
            provider_type = result.provider_type
            dedup_count = result.dedup_count
            dedup_type = result.deduplication_type
            # alerts without provider_id and provider_type are considered as "keep"
            if not provider_type:
                provider_type = "keep"
            key = str(result.deduplication_rule_id)
            if key not in stats:
                # initialize the stats for the deduplication rule
                stats[key] = {
                    "full_dedup_count": 0,
                    "partial_dedup_count": 0,
                    "none_dedup_count": 0,
                    "alerts_last_24_hours": [
                        {"hour": (current_hour - timedelta(hours=i)).hour, "number": 0}
                        for i in range(0, 24)
                    ],
                    "provider_id": provider_id,
                    "provider_type": provider_type,
                }
            if dedup_type == "full":
                stats[key]["full_dedup_count"] += dedup_count
            elif dedup_type == "partial":
                stats[key]["partial_dedup_count"] += dedup_count
            elif dedup_type == "none":
                stats[key]["none_dedup_count"] += dedup_count
        # Add alerts distribution from the last 24 hours
        for result in alerts_last_24_hours_results:
            provider_id = result.provider_id
            provider_type = result.provider_type
            date_hour = result.date_hour
            hourly_count = result.hourly_count
            key = str(result.deduplication_rule_id)
            if not provider_type:
                provider_type = "keep"
            if key in stats:
                hours_ago = int((current_hour - date_hour).total_seconds() / 3600)
                if 0 <= hours_ago < 24:
                    stats[key]["alerts_last_24_hours"][23 - hours_ago]["number"] = (
                        hourly_count
                    )
    return stats


def get_custom_deduplication_rule(tenant_id, provider_id, provider_type):
    with Session(engine) as session:
        rule = session.exec(
            select(AlertDeduplicationRule)
            .where(AlertDeduplicationRule.tenant_id == tenant_id)
            .where(AlertDeduplicationRule.provider_id == provider_id)
            .where(AlertDeduplicationRule.provider_type == provider_type)
        ).first()
    return rule


def get_deduplication_rule_by_id(tenant_id, rule_id: str):
    rule_uuid = __convert_to_uuid(rule_id)
    if not rule_uuid:
        return None
    with Session(engine) as session:
        rules = session.exec(
            select(AlertDeduplicationRule)
            .where(AlertDeduplicationRule.tenant_id == tenant_id)
            .where(AlertDeduplicationRule.id == rule_uuid)
        ).first()
    return rules


def get_extraction_rule_by_id(
    tenant_id: str, rule_id: str, session: Optional[Session] = None
) -> ExtractionRule | None:
    with existed_or_new_session(session) as session:
        query = select(ExtractionRule).where(
            ExtractionRule.tenant_id == tenant_id, ExtractionRule.id == rule_id
        )
        return session.exec(query).first()


def get_mapping_rule_by_id(
    tenant_id: str, rule_id: str, session: Optional[Session] = None
) -> MappingRule | None:
    with existed_or_new_session(session) as session:
        query = select(MappingRule).where(
            MappingRule.tenant_id == tenant_id, MappingRule.id == rule_id
        )
        return session.exec(query).first()


def get_rule(tenant_id, rule_id):
    with Session(engine) as session:
        rule = session.exec(
            select(Rule).where(Rule.tenant_id == tenant_id).where(Rule.id == rule_id)
        ).first()
    return rule


def get_rule_distribution(tenant_id, minute=False):
    """Returns hits per hour for each rule, optionally breaking down by groups if the rule has 'group by', limited to the last 7 days."""
    with Session(engine) as session:
        # Get the timestamp for 7 days ago
        seven_days_ago = dt.now(tz=timezone.utc) - timedelta(days=1)
        # Check the dialect
        if session.bind.dialect.name == "mysql":
            time_format = "%Y-%m-%d %H:%i" if minute else "%Y-%m-%d %H"
            timestamp_format = func.date_format(
                LastAlertToIncident.timestamp, time_format
            )
        elif session.bind.dialect.name == "postgresql":
            time_format = "YYYY-MM-DD HH:MI" if minute else "YYYY-MM-DD HH"
            timestamp_format = func.to_char(LastAlertToIncident.timestamp, time_format)
        elif session.bind.dialect.name == "sqlite":
            time_format = "%Y-%m-%d %H:%M" if minute else "%Y-%m-%d %H"
            timestamp_format = func.strftime(time_format, LastAlertToIncident.timestamp)
        else:
            raise ValueError("Unsupported database dialect")
        # Construct the query
        query = (
            session.query(
                Rule.id.label("rule_id"),
                Rule.name.label("rule_name"),
                Incident.id.label("incident_id"),
                Incident.rule_fingerprint.label("rule_fingerprint"),
                timestamp_format.label("time"),
                func.count(LastAlertToIncident.fingerprint).label("hits"),
            )
            .join(Incident, Rule.id == Incident.rule_id)
            .join(LastAlertToIncident, Incident.id == LastAlertToIncident.incident_id)
            .filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.timestamp >= seven_days_ago,
            )
            .filter(Rule.tenant_id == tenant_id)  # Filter by tenant_id
            .group_by(
                Rule.id, "rule_name", Incident.id, "rule_fingerprint", "time"
            )  # Adjusted here
            .order_by("time")
        )
        results = query.all()
        # Convert the results into a dictionary
        rule_distribution = {}
        for result in results:
            rule_id = result.rule_id
            rule_fingerprint = result.rule_fingerprint
            timestamp = result.time
            hits = result.hits
            if rule_id not in rule_distribution:
                rule_distribution[rule_id] = {}
            if rule_fingerprint not in rule_distribution[rule_id]:
                rule_distribution[rule_id][rule_fingerprint] = {}
            rule_distribution[rule_id][rule_fingerprint][timestamp] = hits
        return rule_distribution


def get_rules(tenant_id, ids=None) -> list[Rule]:
    with Session(engine) as session:
        # Start building the query
        query = (
            select(Rule)
            .where(Rule.tenant_id == tenant_id)
            .where(Rule.is_deleted.is_(False))
        )
        # Apply additional filters if ids are provided
        if ids is not None:
            query = query.where(Rule.id.in_(ids))
        # Execute the query
        rules = session.exec(query).all()
        return rules


def update_deduplication_rule(
    rule_id: str,
    tenant_id: str,
    name: str,
    description: str,
    provider_id: str | None,
    provider_type: str,
    last_updated_by: str,
    enabled: bool = True,
    fingerprint_fields: list[str] = [],
    full_deduplication: bool = False,
    ignore_fields: list[str] = [],
    priority: int = 0,
):
    rule_uuid = __convert_to_uuid(rule_id)
    if not rule_uuid:
        return False
    with Session(engine) as session:
        rule = session.exec(
            select(AlertDeduplicationRule)
            .where(AlertDeduplicationRule.id == rule_uuid)
            .where(AlertDeduplicationRule.tenant_id == tenant_id)
        ).first()
        if not rule:
            raise ValueError(f"No deduplication rule found with id {rule_id}")
        rule.name = name
        rule.description = description
        rule.provider_id = provider_id
        rule.provider_type = provider_type
        rule.last_updated_by = last_updated_by
        rule.enabled = enabled
        rule.fingerprint_fields = fingerprint_fields
        rule.full_deduplication = full_deduplication
        rule.ignore_fields = ignore_fields
        rule.priority = priority
        session.add(rule)
        session.commit()
        session.refresh(rule)
    return rule


def update_rule(
    tenant_id,
    rule_id,
    name,
    timeframe,
    timeunit,
    definition,
    definition_cel,
    updated_by,
    grouping_criteria,
    require_approve,
    resolve_on,
    create_on,
    incident_name_template,
    incident_prefix,
    multi_level,
    multi_level_property_name,
    threshold,
):
    rule_uuid = __convert_to_uuid(rule_id)
    if not rule_uuid:
        return False
    with Session(engine) as session:
        rule = session.exec(
            select(Rule).where(Rule.tenant_id == tenant_id).where(Rule.id == rule_uuid)
        ).first()
        if rule:
            rule.name = name
            rule.timeframe = timeframe
            rule.timeunit = timeunit
            rule.definition = definition
            rule.definition_cel = definition_cel
            rule.grouping_criteria = grouping_criteria
            rule.require_approve = require_approve
            rule.updated_by = updated_by
            rule.update_time = dt.now(tz=timezone.utc)
            rule.resolve_on = resolve_on
            rule.create_on = create_on
            rule.incident_name_template = incident_name_template
            rule.incident_prefix = incident_prefix
            rule.multi_level = multi_level
            rule.multi_level_property_name = multi_level_property_name
            rule.threshold = threshold
            session.commit()
            session.refresh(rule)
            return rule
        else:
            return None
