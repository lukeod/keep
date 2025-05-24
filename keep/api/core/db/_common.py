"""Common database utilities and shared functions."""

import logging
from contextlib import contextmanager
from datetime import datetime as dt, timedelta, timezone
from functools import wraps
from typing import Iterator, List, Type, Optional
from uuid import UUID

from dotenv import find_dotenv, load_dotenv
from opentelemetry import trace  # pylint: disable=import-outside-toplevel
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from retry import retry
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm.exc import StaleDataError
from sqlmodel import Session, SQLModel, col, select

from keep.api.core.config import config
from keep.api.core.db_utils import create_db_engine, get_json_extract_field
from keep.api.models.db.alert import Alert
from keep.api.models.db.helpers import NULL_FOR_DELETED_AT
from keep.api.models.db.incident import Incident
from keep.api.models.db.provider import Provider
from keep.api.models.db.rule import Rule
from keep.api.models.db.tenant import Tenant
from keep.api.models.db.user import User
from keep.api.models.db.workflow import (
    Workflow,
    WorkflowExecution,
)

__all__ = [
    "engine",
    "logger",
    "Session",
    "existed_or_new_session",
    "get_session",
    "get_session_sync",
    "retry_on_db_error",
    "filter_query",
    "get_activity_report",
    "get_resource_ids_by_resource_type",
    "get_table_class",
    "dispose_session",
    "__convert_to_uuid",
    "get_json_extract_field",
    "NULL_FOR_DELETED_AT",
    "ALLOWED_INCIDENT_FILTERS",
    "KEEP_AUDIT_EVENTS_ENABLED",
    "INTERVAL_WORKFLOWS_RELAUNCH_TIMEOUT",
    "WORKFLOWS_TIMEOUT",
]

# this is a workaround for gunicorn to load the env vars
# because somehow in gunicorn it doesn't load the .env file
load_dotenv(find_dotenv())

# Create the engine
logger = logging.getLogger(__name__)
engine = create_db_engine()
SQLAlchemyInstrumentor().instrument(enable_commenter=True, engine=engine)
ALLOWED_INCIDENT_FILTERS = [
    "status",
    "severity",
    "sources",
    "affected_services",
    "assignee",
]
KEEP_AUDIT_EVENTS_ENABLED = config("KEEP_AUDIT_EVENTS_ENABLED", cast=bool, default=True)
INTERVAL_WORKFLOWS_RELAUNCH_TIMEOUT = timedelta(minutes=60)
WORKFLOWS_TIMEOUT = timedelta(minutes=120)


def __convert_to_uuid(value: str, should_raise: bool = False) -> UUID | None:
    try:
        return UUID(value)
    except ValueError:
        if should_raise:
            raise ValueError(f"Invalid UUID: {value}")
        return None


def dispose_session():
    logger.info("Disposing engine pool")
    if engine.dialect.name != "sqlite":
        engine.dispose(close=False)
        logger.info("Engine pool disposed")
    else:
        logger.info("Engine pool is sqlite, not disposing")


@contextmanager
def existed_or_new_session(session: Optional[Session] = None) -> Iterator[Session]:
    try:
        if session:
            yield session
        else:
            with Session(engine) as session:
                yield session
    except Exception as e:
        e.session = session
        raise e


def filter_query(session: Session, query, field, value):
    if session.bind.dialect.name in ["mysql", "postgresql"]:
        if isinstance(value, list):
            if session.bind.dialect.name == "mysql":
                query = query.filter(func.json_overlaps(field, func.json_array(value)))
            else:
                query = query.filter(col(field).op("?|")(func.array(value)))
        else:
            query = query.filter(func.json_contains(field, value))
    elif session.bind.dialect.name == "sqlite":
        json_each_alias = func.json_each(field).table_valued("value")
        subquery = select(1).select_from(json_each_alias)
        if isinstance(value, list):
            subquery = subquery.where(json_each_alias.c.value.in_(value))
        else:
            subquery = subquery.where(json_each_alias.c.value == value)
        query = query.filter(subquery.exists())
    return query


def get_activity_report(session: Optional[Session] = None):
    last_24_hours = dt.now(tz=timezone.utc) - timedelta(hours=24)
    activity_report = {}
    with Session(engine) as session:
        activity_report["tenants_count"] = session.query(Tenant).count()
        activity_report["providers_count"] = session.query(Provider).count()
        activity_report["users_count"] = session.query(User).count()
        activity_report["rules_count"] = session.query(Rule).count()
        activity_report["last_24_hours_incidents_count"] = (
            session.query(Incident)
            .filter(Incident.creation_time >= last_24_hours)
            .count()
        )
        activity_report["last_24_hours_alerts_count"] = (
            session.query(Alert).filter(Alert.timestamp >= last_24_hours).count()
        )
        activity_report["last_24_hours_rules_created"] = (
            session.query(Rule).filter(Rule.creation_time >= last_24_hours).count()
        )
        activity_report["last_24_hours_workflows_created"] = (
            session.query(Workflow)
            .filter(Workflow.creation_time >= last_24_hours)
            .count()
        )
        activity_report["last_24_hours_workflows_executed"] = (
            session.query(WorkflowExecution)
            .filter(WorkflowExecution.started >= last_24_hours)
            .count()
        )
    return activity_report


def get_resource_ids_by_resource_type(
    tenant_id: str, table_name: str, uid: str, session: Optional[Session] = None
) -> List[str]:
    """
    Get all unique IDs from a table grouped by a specified UID column.
    Args:
        tenant_id (str): The tenant ID to filter by
        table_name (str): Name of the table (e.g. "alerts", "rules")
        uid (str): Name of the column to group by
        session (Optional[Session]): SQLModel session
    Returns:
        List[str]: List of unique IDs
    Example:
        >>> get_resource_ids_by_resource_type("tenant123", "alerts", "alert_id")
        ['id1', 'id2', 'id3']
    """
    with existed_or_new_session(session) as session:
        # Get the table class dynamically
        table_class = get_table_class(table_name)
        # Create the query using SQLModel's select
        query = (
            select(getattr(table_class, uid))
            .distinct()
            .where(getattr(table_class, "tenant_id") == tenant_id)
        )
        # Execute the query and return results
        result = session.exec(query)
        return result.all()


def get_session() -> Session:
    """
    Creates a database session.
    Yields:
        Session: A database session
    """
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("get_session"):
        with Session(engine) as session:
            yield session


def get_session_sync() -> Session:
    """
    Creates a database session.
    Returns:
        Session: A database session
    """
    return Session(engine)


def get_table_class(table_name: str) -> Type[SQLModel]:
    """
    Get the SQLModel table class dynamically based on table name.
    Assumes table classes follow PascalCase naming convention.
    Args:
        table_name (str): Name of the table in snake_case (e.g. "alerts", "rules")
    Returns:
        Type[SQLModel]: The corresponding SQLModel table class
    """
    # Convert snake_case to PascalCase and remove trailing 's' if exists
    class_name = "".join(
        word.capitalize() for word in table_name.rstrip("s").split("_")
    )
    # Get all SQLModel subclasses from the imported modules
    model_classes = {
        cls.__name__: cls
        for cls in SQLModel.__subclasses__()
        if hasattr(cls, "__tablename__")
    }
    if class_name not in model_classes:
        raise ValueError(f"No table class found for table name: {table_name}")
    return model_classes[class_name]


def retry_on_db_error(f):
    @retry(
        exceptions=(OperationalError, IntegrityError, StaleDataError),
        tries=3,
        delay=0.1,
        backoff=2,
        jitter=(0, 0.1),
        logger=logger,
    )
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (OperationalError, IntegrityError, StaleDataError) as e:
            if hasattr(e, "session") and not e.session.is_active:
                e.session.rollback()
            if "Deadlock found" in str(e):
                logger.warning(
                    "Deadlock detected, retrying transaction", extra={"error": str(e)}
                )
                raise  # retry will catch this
            else:
                logger.exception(
                    f"Error while executing transaction during {f.__name__}",
                )
            raise  # if it's not a deadlock, let it propagate

    return wrapper
