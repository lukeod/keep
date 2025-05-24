"""Database operations for workflow."""

import json

from datetime import datetime as dt, timedelta, timezone
from typing import List, Union, Optional
from uuid import uuid4
import random

from sqlalchemy import and_, desc, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from sqlmodel import Session, col, or_, select

from keep.api.core.db._common import (
    INTERVAL_WORKFLOWS_RELAUNCH_TIMEOUT,
    WORKFLOWS_TIMEOUT,
    KEEP_AUDIT_EVENTS_ENABLED,
    existed_or_new_session,
)
from keep.api.core.db._common import Session, engine, logger
from keep.api.core.db_utils import custom_serialize, get_or_create
from keep.api.models.db.workflow import *
from keep.api.models.db.workflow import get_dummy_workflow_id
from keep.api.models.time_stamp import TimeStampFilter


def add_or_update_workflow(
    id: str,
    name: str,
    tenant_id: str,
    description: str | None,
    created_by: str,
    interval: int | None,
    workflow_raw: str,
    is_disabled: bool,
    updated_by: str,
    provisioned: bool = False,
    provisioned_file: str | None = None,
    force_update: bool = False,
    is_test: bool = False,
    lookup_by_name: bool = False,
) -> Workflow:
    with Session(engine, expire_on_commit=False) as session:
        if provisioned or lookup_by_name:
            # if workflow is provisioned, we lookup by name to not duplicate workflows on each backend restart
            existing_workflow = get_workflow_by_name(tenant_id, name)
        else:
            # otherwise, we want certainty, so just lookup by id
            existing_workflow = get_workflow_by_id(tenant_id, id)
        if existing_workflow:
            existing_workflow_dict = existing_workflow.model_dump()
            workflow_dict = dict(
                tenant_id=tenant_id,
                name=name,
                description=description,
                interval=interval,
                workflow_raw=workflow_raw,
                is_disabled=is_disabled,
                is_test=is_test,
                is_deleted=False,
                provisioned=provisioned,
                provisioned_file=provisioned_file,
            )
            if (
                is_equal_workflow_dicts(existing_workflow_dict, workflow_dict)
                and not force_update
            ):
                logger.info(
                    f"Workflow {id} already exists with the same workflow properties, skipping update"
                )
                return existing_workflow
            return update_workflow_with_values(
                existing_workflow,
                name=name,
                description=description,
                interval=interval,
                workflow_raw=workflow_raw,
                is_disabled=is_disabled,
                provisioned=provisioned,
                provisioned_file=provisioned_file,
                updated_by=updated_by,
                session=session,
            )
        else:
            now = dt.now(tz=timezone.utc)
            # Create a new workflow
            workflow = Workflow(
                id=id,
                revision=1,
                name=name,
                tenant_id=tenant_id,
                description=description,
                created_by=created_by,
                updated_by=updated_by,
                last_updated=now,
                interval=interval,
                is_disabled=is_disabled,
                workflow_raw=workflow_raw,
                provisioned=provisioned,
                provisioned_file=provisioned_file,
                is_test=is_test,
            )
            version = WorkflowVersion(
                workflow_id=workflow.id,
                revision=1,
                workflow_raw=workflow_raw,
                updated_by=updated_by,
                comment=f"Created by {created_by}",
                is_valid=True,
                is_current=True,
                updated_at=now,
            )
            session.add(workflow)
            session.add(version)
            session.commit()
            return workflow


def create_workflow_execution(
    workflow_id: str,
    workflow_revision: int,
    tenant_id: str,
    triggered_by: str,
    execution_number: int = 1,
    event_id: str = None,
    fingerprint: str = None,
    execution_id: str = None,
    event_type: str = "alert",
    test_run: bool = False,
) -> str:
    with Session(engine) as session:
        try:
            workflow_execution_id = execution_id or (
                str(uuid4()) if not test_run else "test_" + str(uuid4())
            )
            if len(triggered_by) > 255:
                triggered_by = triggered_by[:255]
            workflow_execution = WorkflowExecution(
                id=workflow_execution_id,
                workflow_id=workflow_id,
                workflow_revision=workflow_revision,
                tenant_id=tenant_id,
                started=dt.now(tz=timezone.utc),
                triggered_by=triggered_by,
                execution_number=execution_number,
                status="in_progress",
                error=None,
                execution_time=None,
                results={},
                is_test_run=test_run,
            )
            session.add(workflow_execution)
            # Ensure the object has an id
            session.flush()
            execution_id = workflow_execution.id
            if KEEP_AUDIT_EVENTS_ENABLED:
                if fingerprint and event_type == "alert":
                    workflow_to_alert_execution = WorkflowToAlertExecution(
                        workflow_execution_id=execution_id,
                        alert_fingerprint=fingerprint,
                        event_id=event_id,
                    )
                    session.add(workflow_to_alert_execution)
                elif event_type == "incident":
                    workflow_to_incident_execution = WorkflowToIncidentExecution(
                        workflow_execution_id=execution_id,
                        alert_fingerprint=fingerprint,
                        incident_id=event_id,
                    )
                    session.add(workflow_to_incident_execution)
            session.commit()
            return execution_id
        except IntegrityError:
            session.rollback()
            logger.debug(
                f"Failed to create a new execution for workflow {workflow_id}. Constraint is met."
            )
            raise


def delete_workflow(tenant_id, workflow_id):
    with Session(engine) as session:
        workflow = session.exec(
            select(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.id == workflow_id)
        ).first()
        if workflow:
            workflow.is_deleted = True
            session.commit()


def delete_workflow_by_provisioned_file(tenant_id, provisioned_file):
    with Session(engine) as session:
        workflow = session.exec(
            select(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.provisioned_file == provisioned_file)
        ).first()
        if workflow:
            workflow.is_deleted = True
            session.commit()


def finish_workflow_execution(tenant_id, workflow_id, execution_id, status, error):
    with Session(engine) as session:
        workflow_execution = session.exec(
            select(WorkflowExecution).where(WorkflowExecution.id == execution_id)
        ).first()
        # some random number to avoid collisions
        if not workflow_execution:
            logger.warning(
                f"Failed to finish workflow execution {execution_id} for workflow {workflow_id}. Execution not found.",
                extra={
                    "tenant_id": tenant_id,
                    "workflow_id": workflow_id,
                    "workflow_execution_id": execution_id,
                },
            )
            raise ValueError("Execution not found")
        workflow_execution.is_running = random.randint(1, 2147483647 - 1)  # max int
        workflow_execution.status = status
        # TODO: we had a bug with the error field, it was too short so some customers may fail over it.
        #   we need to fix it in the future, create a migration that increases the size of the error field
        #   and then we can remove the [:511] from here
        workflow_execution.error = error[:511] if error else None
        execution_time = (
            dt.now(tz=timezone.utc) - workflow_execution.started
        ).total_seconds()
        workflow_execution.execution_time = int(execution_time)
        # TODO: logs
        session.commit()
        logger.info(
            f"Finished workflow execution {execution_id} for workflow {workflow_id} with status {status}",
            extra={
                "tenant_id": tenant_id,
                "workflow_id": workflow_id,
                "workflow_execution_id": execution_id,
                "execution_time": execution_time,
            },
        )


def get_all_provisioned_workflows(tenant_id: str):
    with Session(engine) as session:
        workflows = session.exec(
            select(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.provisioned == True)
            .where(Workflow.is_deleted == False)
            .where(Workflow.is_test == False)
        ).all()
    return list(workflows)


def get_all_workflows(tenant_id: str, exclude_disabled: bool = False) -> List[Workflow]:
    with Session(engine) as session:
        query = (
            select(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.is_deleted == False)
            .where(Workflow.is_test == False)
        )
        if exclude_disabled:
            query = query.where(Workflow.is_disabled == False)
        workflows = session.exec(query).all()
    return workflows


def get_all_workflows_yamls(tenant_id: str):
    with Session(engine) as session:
        workflows = session.exec(
            select(Workflow.workflow_raw)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.is_deleted == False)
            .where(Workflow.is_test == False)
        ).all()
    return list(workflows)


def get_combined_workflow_execution_distribution(
    tenant_id: str, timestamp_filter: TimeStampFilter = None
):
    """
    Calculate the distribution of WorkflowExecutions started over time, combined across all workflows for a specific tenant.
    Args:
        tenant_id (str): ID of the tenant whose workflow executions are being analyzed.
        timestamp_filter (TimeStampFilter, optional): Filter to specify the time range.
            - lower_timestamp (dt): Start of the time range.
            - upper_timestamp (dt): End of the time range.
    Returns:
        List[dict]: A list of dictionaries representing the hourly distribution of workflow executions.
            Each dictionary contains:
            - 'timestamp' (str): Timestamp of the hour in "YYYY-MM-DD HH:00" format.
            - 'number' (int): Number of workflow executions started in that hour.
    Notes:
        - If no timestamp_filter is provided, defaults to the last 24 hours.
        - Supports MySQL, PostgreSQL, and SQLite for timestamp formatting.
    """
    with Session(engine) as session:
        twenty_four_hours_ago = dt.now(tz=timezone.utc) - timedelta(hours=24)
        time_format = "%Y-%m-%d %H"
        filters = [WorkflowExecution.tenant_id == tenant_id]
        if timestamp_filter:
            if timestamp_filter.lower_timestamp:
                filters.append(
                    WorkflowExecution.started >= timestamp_filter.lower_timestamp
                )
            if timestamp_filter.upper_timestamp:
                filters.append(
                    WorkflowExecution.started <= timestamp_filter.upper_timestamp
                )
        else:
            filters.append(WorkflowExecution.started >= twenty_four_hours_ago)
        # Database-specific timestamp formatting
        if session.bind.dialect.name == "mysql":
            timestamp_format = func.date_format(WorkflowExecution.started, time_format)
        elif session.bind.dialect.name == "postgresql":
            timestamp_format = func.to_char(WorkflowExecution.started, "YYYY-MM-DD HH")
        elif session.bind.dialect.name == "sqlite":
            timestamp_format = func.strftime(time_format, WorkflowExecution.started)
        # Query for combined execution count across all workflows
        query = (
            session.query(
                timestamp_format.label("time"),
                func.count().label("executions"),
            )
            .filter(*filters)
            .group_by("time")
            .order_by("time")
        )
        results = {str(time): executions for time, executions in query.all()}
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


def get_last_completed_execution(
    session: Session, workflow_id: str
) -> WorkflowExecution:
    return session.exec(
        select(WorkflowExecution)
        .where(WorkflowExecution.workflow_id == workflow_id)
        .where(WorkflowExecution.is_test_run == False)
        .where(
            (WorkflowExecution.status == "success")
            | (WorkflowExecution.status == "error")
            | (WorkflowExecution.status == "providers_not_configured")
        )
        .order_by(WorkflowExecution.execution_number.desc())
        .limit(1)
    ).first()


def get_last_workflow_execution_by_workflow_id(
    tenant_id: str,
    workflow_id: str,
    status: str | None = None,
    exclude_ids: list[str] | None = None,
) -> Optional[WorkflowExecution]:
    with Session(engine) as session:
        query = (
            select(WorkflowExecution)
            .where(WorkflowExecution.workflow_id == workflow_id)
            .where(WorkflowExecution.tenant_id == tenant_id)
            .where(WorkflowExecution.started >= dt.now(tz=timezone.utc) - timedelta(days=1))
            .order_by(col(WorkflowExecution.started).desc())
        )
        if status:
            query = query.where(WorkflowExecution.status == status)
        if exclude_ids:
            query = query.where(col(WorkflowExecution.id).notin_(exclude_ids))
        workflow_execution = session.exec(query).first()
    return workflow_execution


def get_last_workflow_executions(tenant_id: str, limit=20):
    with Session(engine) as session:
        execution_with_logs = (
            session.query(WorkflowExecution)
            .filter(
                WorkflowExecution.tenant_id == tenant_id,
            )
            .order_by(desc(WorkflowExecution.started))
            .limit(limit)
            .options(joinedload(WorkflowExecution.logs))
            .all()
        )
        return execution_with_logs


def get_or_create_dummy_workflow(tenant_id: str, session: Session | None = None):
    with existed_or_new_session(session) as session:
        workflow, created = get_or_create(
            session,
            Workflow,
            tenant_id=tenant_id,
            id=get_dummy_workflow_id(tenant_id),
            name="Dummy Workflow for test runs",
            description="Auto-generated dummy workflow for test runs",
            created_by="system",
            workflow_raw="{}",
            is_disabled=False,
            is_test=True,
        )
        if created:
            # For new instances, make sure they're committed and refreshed from the database
            session.commit()
            session.refresh(workflow)
        elif workflow:
            # For existing instances, refresh to get the current state
            session.refresh(workflow)
        return workflow


def get_previous_execution_id(tenant_id, workflow_id, workflow_execution_id):
    with Session(engine) as session:
        previous_execution = session.exec(
            select(WorkflowExecution)
            .where(WorkflowExecution.tenant_id == tenant_id)
            .where(WorkflowExecution.workflow_id == workflow_id)
            .where(WorkflowExecution.id != workflow_execution_id)
            .where(WorkflowExecution.is_test_run == False)
            .where(
                WorkflowExecution.started >= dt.now(tz=timezone.utc) - timedelta(days=1)
            )  # no need to check more than 1 day ago
            .order_by(WorkflowExecution.started.desc())
            .limit(1)
        ).first()
        if previous_execution:
            return previous_execution
        else:
            return None


def get_timeouted_workflow_exections():
    with Session(engine) as session:
        logger.debug("Checking for timeouted workflows")
        timeouted_workflows = []
        try:
            result = session.exec(
                select(WorkflowExecution)
                .filter(WorkflowExecution.status == "in_progress")
                .filter(
                    WorkflowExecution.started <= dt.now(tz=timezone.utc) - WORKFLOWS_TIMEOUT
                )
            )
            timeouted_workflows = result.all()
        except Exception as e:
            logger.exception("Failed to get timeouted workflows: ", e)
        logger.debug(f"Found {len(timeouted_workflows)} timeouted workflows")
        return timeouted_workflows


def get_workflow_by_id(tenant_id: str, workflow_id: str):
    with Session(engine) as session:
        workflow = session.exec(
            select(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.id == workflow_id)
            .where(Workflow.is_deleted == False)
            .where(Workflow.is_test == False)
        ).first()
    return workflow


def get_workflow_by_name(tenant_id, workflow_name):
    with Session(engine) as session:
        workflow = session.exec(
            select(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.name == workflow_name)
            .where(Workflow.is_deleted == False)
        ).first()
        return workflow


def get_workflow_execution(
    tenant_id: str, workflow_execution_id: str, is_test_run: bool | None = None
):
    with Session(engine) as session:
        base_query = session.query(WorkflowExecution)
        if is_test_run is not None:
            base_query = base_query.filter(
                WorkflowExecution.is_test_run == is_test_run,
            )
        base_query = base_query.filter(
            WorkflowExecution.id == workflow_execution_id,
            WorkflowExecution.tenant_id == tenant_id,
        )
        execution_with_logs = base_query.options(
            joinedload(WorkflowExecution.logs),
            joinedload(WorkflowExecution.workflow_to_alert_execution),
            joinedload(WorkflowExecution.workflow_to_incident_execution),
        ).one()
    return execution_with_logs


def get_workflow_executions(
    tenant_id,
    workflow_id,
    limit=50,
    offset=0,
    tab=2,
    status: Optional[Union[str, List[str]]] = None,
    trigger: Optional[Union[str, List[str]]] = None,
    execution_id: Optional[str] = None,
    is_test_run: bool = False,
):
    with Session(engine) as session:
        query = session.query(
            WorkflowExecution,
        ).filter(
            WorkflowExecution.tenant_id == tenant_id,
            WorkflowExecution.workflow_id == workflow_id,
            WorkflowExecution.is_test_run == False,
        )
        now = dt.now(tz=timezone.utc)
        timeframe = None
        if tab == 1:
            timeframe = now - timedelta(days=30)
        elif tab == 2:
            timeframe = now - timedelta(days=7)
        elif tab == 3:
            start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            query = query.filter(
                WorkflowExecution.started >= start_of_day,
                WorkflowExecution.started <= now,
            )
        if timeframe:
            query = query.filter(WorkflowExecution.started >= timeframe)
        if isinstance(status, str):
            status = [status]
        elif status is None:
            status = []
        # Normalize trigger to a list
        if isinstance(trigger, str):
            trigger = [trigger]
        if execution_id:
            query = query.filter(WorkflowExecution.id == execution_id)
        if status and len(status) > 0:
            query = query.filter(WorkflowExecution.status.in_(status))
        if trigger and len(trigger) > 0:
            conditions = [
                WorkflowExecution.triggered_by.like(f"{trig}%") for trig in trigger
            ]
            query = query.filter(or_(*conditions))
        total_count = query.count()
        status_count_query = query.with_entities(
            WorkflowExecution.status, func.count().label("count")
        ).group_by(WorkflowExecution.status)
        status_counts = status_count_query.all()
        statusGroupbyMap = {status: count for status, count in status_counts}
        pass_count = statusGroupbyMap.get("success", 0)
        fail_count = statusGroupbyMap.get("error", 0) + statusGroupbyMap.get(
            "timeout", 0
        )
        avgDuration = query.with_entities(
            func.avg(WorkflowExecution.execution_time)
        ).scalar()
        avgDuration = avgDuration if avgDuration else 0.0
        query = (
            query.order_by(desc(WorkflowExecution.started)).limit(limit).offset(offset)
        )
        # Execute the query
        workflow_executions = query.all()
    return total_count, workflow_executions, pass_count, fail_count, avgDuration


def get_workflow_executions_count(tenant_id: str):
    with Session(engine) as session:
        query = session.query(WorkflowExecution).filter(
            WorkflowExecution.tenant_id == tenant_id,
        )
        return {
            "success": query.filter(WorkflowExecution.status == "success").count(),
            "other": query.filter(WorkflowExecution.status != "success").count(),
        }


def get_workflow_id(tenant_id, workflow_name):
    with Session(engine) as session:
        workflow = session.exec(
            select(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.name == workflow_name)
            .where(Workflow.is_deleted == False)
        ).first()
        if workflow:
            return workflow.id


def get_workflow_version(tenant_id: str, workflow_id: str, revision: int):
    with Session(engine) as session:
        version = session.exec(
            select(WorkflowVersion)
            # starting from the 'workflow' table since it's smaller
            .select_from(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.id == workflow_id)
            .where(Workflow.is_deleted == False)
            .join(WorkflowVersion, WorkflowVersion.workflow_id == Workflow.id)
            .where(WorkflowVersion.revision == revision)
        ).first()
    return version


def get_workflow_versions(tenant_id: str, workflow_id: str):
    with Session(engine) as session:
        versions = session.exec(
            select(WorkflowVersion)
            # starting from the 'workflow' table since it's smaller
            .select_from(Workflow)
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.id == workflow_id)
            .where(Workflow.is_deleted == False)
            .join(WorkflowVersion, WorkflowVersion.workflow_id == Workflow.id)
            .order_by(WorkflowVersion.revision.desc())
        ).all()
    return versions


def get_workflows_that_should_run():
    with Session(engine) as session:
        logger.debug("Checking for workflows that should run")
        workflows_with_interval = []
        try:
            result = session.exec(
                select(Workflow)
                .filter(Workflow.is_deleted == False)
                .filter(Workflow.is_disabled == False)
                .filter(Workflow.interval != None)
                .filter(Workflow.interval > 0)
            )
            workflows_with_interval = result.all() if result else []
        except Exception:
            logger.exception("Failed to get workflows with interval")
        logger.debug(f"Found {len(workflows_with_interval)} workflows with interval")
        workflows_to_run = []
        # for each workflow:
        for workflow in workflows_with_interval:
            current_time = dt.now(tz=timezone.utc)
            last_execution = get_last_completed_execution(session, workflow.id)
            # if there no last execution, that's the first time we run the workflow
            if not last_execution:
                try:
                    # try to get the lock
                    workflow_execution_id = create_workflow_execution(
                        workflow.id, workflow.revision, workflow.tenant_id, "scheduler"
                    )
                    # we succeed to get the lock on this execution number :)
                    # let's run it
                    workflows_to_run.append(
                        {
                            "tenant_id": workflow.tenant_id,
                            "workflow_id": workflow.id,
                            "workflow_execution_id": workflow_execution_id,
                        }
                    )
                # some other thread/instance has already started to work on it
                except IntegrityError:
                    continue
            # else, if the last execution was more than interval seconds ago, we need to run it
            elif (
                last_execution.started + timedelta(seconds=workflow.interval)
                <= current_time
            ):
                try:
                    # try to get the lock with execution_number + 1
                    workflow_execution_id = create_workflow_execution(
                        workflow.id,
                        workflow.revision,
                        workflow.tenant_id,
                        "scheduler",
                        last_execution.execution_number + 1,
                    )
                    # we succeed to get the lock on this execution number :)
                    # let's run it
                    workflows_to_run.append(
                        {
                            "tenant_id": workflow.tenant_id,
                            "workflow_id": workflow.id,
                            "workflow_execution_id": workflow_execution_id,
                        }
                    )
                    # continue to the next one
                    continue
                # some other thread/instance has already started to work on it
                except IntegrityError:
                    # we need to verify the locking is still valid and not timeouted
                    session.rollback()
                    pass
                # get the ongoing execution
                ongoing_execution = session.exec(
                    select(WorkflowExecution)
                    .where(WorkflowExecution.workflow_id == workflow.id)
                    .where(
                        WorkflowExecution.execution_number
                        == last_execution.execution_number + 1
                    )
                    .limit(1)
                ).first()
                # this is a WTF exception since if this (workflow_id, execution_number) does not exist,
                # we would be able to acquire the lock
                if not ongoing_execution:
                    logger.error(
                        f"WTF: ongoing execution not found {workflow.id} {last_execution.execution_number + 1}"
                    )
                    continue
                # if this completed, error, than that's ok - the service who locked the execution is done
                elif ongoing_execution.status != "in_progress":
                    continue
                # if the ongoing execution runs more than timeout minutes, relaunch it
                elif (
                    ongoing_execution.started + INTERVAL_WORKFLOWS_RELAUNCH_TIMEOUT
                    <= current_time
                ):
                    ongoing_execution.status = "timeout"
                    session.commit()
                    # re-create the execution and try to get the lock
                    try:
                        workflow_execution_id = create_workflow_execution(
                            workflow.id,
                            workflow.revision,
                            workflow.tenant_id,
                            "scheduler",
                            ongoing_execution.execution_number + 1,
                        )
                    # some other thread/instance has already started to work on it and that's ok
                    except IntegrityError:
                        logger.debug(
                            f"Failed to create a new execution for workflow {workflow.id} [timeout]. Constraint is met."
                        )
                        continue
                    # managed to acquire the (workflow_id, execution_number) lock
                    workflows_to_run.append(
                        {
                            "tenant_id": workflow.tenant_id,
                            "workflow_id": workflow.id,
                            "workflow_execution_id": workflow_execution_id,
                        }
                    )
            else:
                logger.debug(
                    f"Workflow {workflow.id} is already running by someone else"
                )
        return workflows_to_run


def get_workflows_with_last_execution(tenant_id: str) -> List[dict]:
    with Session(engine) as session:
        latest_execution_cte = (
            select(
                WorkflowExecution.workflow_id,
                func.max(WorkflowExecution.started).label("last_execution_time"),
            )
            .where(WorkflowExecution.tenant_id == tenant_id)
            .where(
                WorkflowExecution.started
                >= dt.now(tz=timezone.utc) - timedelta(days=7)
            )
            .group_by(WorkflowExecution.workflow_id)
            .limit(1000)
            .cte("latest_execution_cte")
        )
        workflows_with_last_execution_query = (
            select(
                Workflow,
                latest_execution_cte.c.last_execution_time,
                WorkflowExecution.status,
            )
            .outerjoin(
                latest_execution_cte,
                Workflow.id == latest_execution_cte.c.workflow_id,
            )
            .outerjoin(
                WorkflowExecution,
                and_(
                    Workflow.id == WorkflowExecution.workflow_id,
                    WorkflowExecution.started
                    == latest_execution_cte.c.last_execution_time,
                ),
            )
            .where(Workflow.tenant_id == tenant_id)
            .where(Workflow.is_deleted == False)
            .where(Workflow.is_test == False)
        ).distinct()
        result = session.execute(workflows_with_last_execution_query).all()
    return result


def is_equal_workflow_dicts(a: dict, b: dict):
    return (
        a.get("workflow_raw") == b.get("workflow_raw")
        and a.get("tenant_id") == b.get("tenant_id")
        and a.get("is_test") == b.get("is_test")
        and a.get("is_deleted") == b.get("is_deleted")
        and a.get("is_disabled") == b.get("is_disabled")
        and a.get("name") == b.get("name")
        and a.get("description") == b.get("description")
        and a.get("interval") == b.get("interval")
        and a.get("provisioned") == b.get("provisioned")
        and a.get("provisioned_file") == b.get("provisioned_file")
    )


def save_workflow_results(tenant_id, workflow_execution_id, workflow_results):
    with Session(engine) as session:
        workflow_execution = session.exec(
            select(WorkflowExecution)
            .where(WorkflowExecution.tenant_id == tenant_id)
            .where(WorkflowExecution.id == workflow_execution_id)
        ).one()
        try:
            # backward comptability - try to serialize the workflow results
            json.dumps(workflow_results)
            # if that's ok, use the original way
            workflow_execution.results = workflow_results
        except Exception:
            # if that's not ok, use the Keep way (e.g. alerdto is not json serializable)
            logger.warning(
                "Failed to serialize workflow results, using fastapi encoder",
            )
            # use some other way to serialize the workflow results
            workflow_execution.results = custom_serialize(workflow_results)
        # commit the changes
        session.commit()


def update_workflow_by_id(
    id: str,
    name: str,
    tenant_id: str,
    description: str | None,
    interval: int,
    workflow_raw: str,
    is_disabled: bool,
    updated_by: str,
    provisioned: bool = False,
    provisioned_file: str | None = None,
):
    with Session(engine, expire_on_commit=False) as session:
        if provisioned:
            # if workflow is provisioned, we lookup by name to not duplicate workflows on each backend restart
            existing_workflow = get_workflow_by_name(tenant_id, name)
        else:
            # otherwise, we want certainty, so just lookup by id
            existing_workflow = get_workflow_by_id(tenant_id, id)
        if not existing_workflow:
            raise ValueError("Workflow not found")
        return update_workflow_with_values(
            existing_workflow,
            name=name,
            description=description,
            interval=interval,
            workflow_raw=workflow_raw,
            is_disabled=is_disabled,
            provisioned=provisioned,
            provisioned_file=provisioned_file,
            updated_by=updated_by,
            session=session,
        )


def update_workflow_with_values(
    existing_workflow: Workflow,
    name: str,
    description: str | None,
    interval: int | None,
    workflow_raw: str,
    is_disabled: bool,
    updated_by: str,
    provisioned: bool = False,
    provisioned_file: str | None = None,
    session: Session | None = None,
):
    # In case the workflow name changed to empty string, keep the old name
    name = name or existing_workflow.name
    with existed_or_new_session(session) as session:
        # Get the latest revision number for this workflow
        latest_version = session.exec(
            select(WorkflowVersion)
            .where(col(WorkflowVersion.workflow_id) == existing_workflow.id)
            .order_by(col(WorkflowVersion.revision).desc())
            .limit(1)
        ).first()
        next_revision = (latest_version.revision if latest_version else 0) + 1
        # Update all existing versions to not be current
        session.exec(
            update(WorkflowVersion)
            .where(col(WorkflowVersion.workflow_id) == existing_workflow.id)
            .values(is_current=False)  # type: ignore[attr-defined]
        )
        # creating a new version
        version = WorkflowVersion(
            workflow_id=existing_workflow.id,
            revision=next_revision,
            workflow_raw=workflow_raw,
            updated_by=updated_by,
            comment=f"Updated by {updated_by}",
            # TODO: check if valid
            is_valid=True,
            is_current=True,
            updated_at=dt.now(tz=timezone.utc),
        )
        session.add(version)
        existing_workflow.name = name
        existing_workflow.description = description
        existing_workflow.updated_by = updated_by
        existing_workflow.interval = interval
        existing_workflow.workflow_raw = workflow_raw
        existing_workflow.revision = next_revision
        existing_workflow.last_updated = dt.now(tz=timezone.utc)
        existing_workflow.is_deleted = False
        existing_workflow.is_disabled = is_disabled
        existing_workflow.provisioned = provisioned
        existing_workflow.provisioned_file = provisioned_file
        session.add(existing_workflow)
        session.commit()
        return existing_workflow


def push_logs_to_db(log_entries):
    # avoid circular import
    from keep.api.logging import LOG_FORMAT, LOG_FORMAT_OPEN_TELEMETRY

    db_log_entries = []
    if LOG_FORMAT == LOG_FORMAT_OPEN_TELEMETRY:
        for log_entry in log_entries:
            try:
                try:
                    # after formatting
                    message = log_entry["message"][0:255]
                except Exception:
                    # before formatting, fallback
                    message = log_entry["msg"][0:255]
                try:
                    timestamp = dt.strptime(
                        log_entry["asctime"], "%Y-%m-%d %H:%M:%S,%f"
                    )
                except Exception:
                    timestamp = log_entry["created"]
                log_entry = WorkflowExecutionLog(
                    workflow_execution_id=log_entry["workflow_execution_id"],
                    timestamp=timestamp,
                    message=message,
                    context=json.loads(
                        json.dumps(log_entry.get("context", {}), default=str)
                    ),  # workaround to serialize any object
                )
                db_log_entries.append(log_entry)
            except Exception:
                print("Failed to parse log entry - ", log_entry)
    else:
        for log_entry in log_entries:
            try:
                try:
                    # after formatting
                    message = log_entry["message"][0:255]
                except Exception:
                    # before formatting, fallback
                    message = log_entry["msg"][0:255]
                log_entry = WorkflowExecutionLog(
                    workflow_execution_id=log_entry["workflow_execution_id"],
                    timestamp=log_entry["created"],
                    message=message,  # limit the message to 255 chars
                    context=json.loads(
                        json.dumps(log_entry.get("context", {}), default=str)
                    ),  # workaround to serialize any object
                )
                db_log_entries.append(log_entry)
            except Exception:
                print("Failed to parse log entry - ", log_entry)
    # Add the LogEntry instances to the database session
    with Session(engine) as session:
        session.add_all(db_log_entries)
        session.commit()
