"""Database operations for provider."""

from datetime import datetime as datetime_class, timedelta, timezone

from typing import Any, List, Tuple, Optional, Union, Dict

from sqlalchemy import desc, func, select
from sqlalchemy.sql import exists
from sqlmodel import Session, select

from keep.api.core.db._common import Session, engine, logger
from keep.api.models.db.alert import Alert
from keep.api.models.db.provider import *
from keep.api.models.db.provider_image import *
from keep.api.models.time_stamp import TimeStampFilter


def get_all_provisioned_providers(tenant_id: str) -> List[Provider]:
    with Session(engine) as session:
        providers = session.exec(
            select(Provider)
            .where(Provider.tenant_id == tenant_id)
            .where(Provider.provisioned == True)
        ).all()
    return list(providers)


def get_consumer_providers() -> List[Provider]:
    # get all the providers that installed as consumers
    with Session(engine) as session:
        providers = session.exec(
            select(Provider).where(Provider.consumer == True)
        ).all()
    return providers


def get_installed_providers(tenant_id: str) -> List[Provider]:
    with Session(engine) as session:
        providers = session.exec(
            select(Provider).where(Provider.tenant_id == tenant_id)
        ).all()
    return providers


def get_linked_providers(tenant_id: str) -> List[Tuple[str, str, "datetime"]]:
    # Alert table may be too huge, so cutting the query without mercy
    LIMIT_BY_ALERTS = 10000
    with Session(engine) as session:
        alerts_subquery = (
            select(Alert)
            .filter(Alert.tenant_id == tenant_id, Alert.provider_type != "group")
            .limit(LIMIT_BY_ALERTS)
            .subquery()
        )
        providers = session.exec(
            select(
                alerts_subquery.c.provider_type,
                alerts_subquery.c.provider_id,
                func.max(alerts_subquery.c.timestamp).label("last_alert_timestamp"),
            )
            .select_from(alerts_subquery)
            .filter(~exists().where(Provider.id == alerts_subquery.c.provider_id))
            .group_by(alerts_subquery.c.provider_type, alerts_subquery.c.provider_id)
        ).all()
    return providers


def get_provider_by_name(tenant_id: str, provider_name: str) -> Provider:
    with Session(engine) as session:
        provider = session.exec(
            select(Provider)
            .where(Provider.tenant_id == tenant_id)
            .where(Provider.name == provider_name)
        ).first()
    return provider


def get_provider_by_type_and_id(
    tenant_id: str, provider_type: str, provider_id: Optional[str]
) -> Provider:
    with Session(engine) as session:
        query = select(Provider).where(
            Provider.tenant_id == tenant_id,
            Provider.type == provider_type,
            Provider.id == provider_id,
        )
        provider = session.exec(query).first()
    return provider


def get_provider_distribution(
    tenant_id: str,
    aggregate_all: bool = False,
    timestamp_filter: TimeStampFilter = None,
) -> (
    list[dict[str, int | Any]]
    | Dict[str, Dict[str, Union[datetime_class, List[Dict[str, int]], Any]]]
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
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        time_format = "%Y-%m-%d %H"
        filters = [Alert.tenant_id == tenant_id]
        if timestamp_filter:
            if timestamp_filter.lower_timestamp:
                filters.append(Alert.timestamp >= timestamp_filter.lower_timestamp)
            if timestamp_filter.upper_timestamp:
                filters.append(Alert.timestamp <= timestamp_filter.upper_timestamp)
        else:
            filters.append(Alert.timestamp >= twenty_four_hours_ago)
        if session.bind.dialect.name == "mysql":
            timestamp_format = func.date_format(Alert.timestamp, time_format)
        elif session.bind.dialect.name == "postgresql":
            # PostgreSQL requires a different syntax for the timestamp format
            # cf: https://www.postgresql.org/docs/current/functions-formatting.html#FUNCTIONS-FORMATTING
            timestamp_format = func.to_char(Alert.timestamp, "YYYY-MM-DD HH")
        elif session.bind.dialect.name == "sqlite":
            timestamp_format = func.strftime(time_format, Alert.timestamp)
        if aggregate_all:
            # Query for combined alert distribution across all providers
            query = (
                session.query(
                    timestamp_format.label("time"), func.count().label("hits")
                )
                .filter(*filters)
                .group_by("time")
                .order_by("time")
            )
            results = query.all()
            results = {str(time): hits for time, hits in results}
            # Create a complete list of timestamps within the specified range
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
        else:
            # Query for alert distribution grouped by provider
            query = (
                session.query(
                    Alert.provider_id,
                    Alert.provider_type,
                    timestamp_format.label("time"),
                    func.count().label("hits"),
                    func.max(Alert.timestamp).label("last_alert_timestamp"),
                )
                .filter(*filters)
                .group_by(Alert.provider_id, Alert.provider_type, "time")
                .order_by(Alert.provider_id, Alert.provider_type, "time")
            )
            results = query.all()
            provider_distribution = {}
            for provider_id, provider_type, time, hits, last_alert_timestamp in results:
                provider_key = f"{provider_id}_{provider_type}"
                last_alert_timestamp = (
                    datetime.fromisoformat(last_alert_timestamp)
                    if isinstance(last_alert_timestamp, str)
                    else last_alert_timestamp
                )
                if provider_key not in provider_distribution:
                    provider_distribution[provider_key] = {
                        "provider_id": provider_id,
                        "provider_type": provider_type,
                        "alert_last_24_hours": [
                            {"hour": i, "number": 0} for i in range(24)
                        ],
                        "last_alert_received": last_alert_timestamp,
                    }
                else:
                    provider_distribution[provider_key]["last_alert_received"] = max(
                        provider_distribution[provider_key]["last_alert_received"],
                        last_alert_timestamp,
                    )
                time = datetime.strptime(time, time_format)
                index = int((time - twenty_four_hours_ago).total_seconds() // 3600)
                if 0 <= index < 24:
                    provider_distribution[provider_key]["alert_last_24_hours"][index][
                        "number"
                    ] += hits
            return provider_distribution


def get_provider_logs(
    tenant_id: str, provider_id: str, limit: int = 100
) -> List[ProviderExecutionLog]:
    with Session(engine) as session:
        logs = (
            session.query(ProviderExecutionLog)
            .filter(
                ProviderExecutionLog.tenant_id == tenant_id,
                ProviderExecutionLog.provider_id == provider_id,
            )
            .order_by(desc(ProviderExecutionLog.timestamp))
            .limit(limit)
            .all()
        )
    return logs


def is_linked_provider(tenant_id: str, provider_id: str) -> bool:
    with Session(engine) as session:
        query = session.query(Alert.provider_id)
        # Add FORCE INDEX hint only for MySQL
        if engine.dialect.name == "mysql":
            query = query.with_hint(Alert, "FORCE INDEX (idx_alert_tenant_provider)")
        linked_provider = (
            query.outerjoin(Provider, Alert.provider_id == Provider.id)
            .filter(
                Alert.tenant_id == tenant_id,
                Alert.provider_id == provider_id,
                Provider.id == None,
            )
            .first()
        )
    return linked_provider is not None


def update_provider_last_pull_time(tenant_id: str, provider_id: str):
    extra = {"tenant_id": tenant_id, "provider_id": provider_id}
    logger.info("Updating provider last pull time", extra=extra)
    with Session(engine) as session:
        provider = session.exec(
            select(Provider).where(
                Provider.tenant_id == tenant_id, Provider.id == provider_id
            )
        ).first()
        if not provider:
            logger.warning(
                "Could not update provider last pull time since provider does not exist",
                extra=extra,
            )
        try:
            provider.last_pull_time = datetime.now(tz=timezone.utc)
            session.commit()
        except Exception:
            logger.exception("Failed to update provider last pull time", extra=extra)
            raise
    logger.info("Successfully updated provider last pull time", extra=extra)
