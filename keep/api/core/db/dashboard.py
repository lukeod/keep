"""Database operations for dashboard."""

import json

from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import select
from sqlmodel import Session, or_, select

from keep.api.core.db._common import Session, engine
from keep.api.models.db.dashboard import *


def create_dashboard(
    tenant_id, dashboard_name, created_by, dashboard_config, is_private=False
):
    with Session(engine) as session:
        dashboard = Dashboard(
            tenant_id=tenant_id,
            dashboard_name=dashboard_name,
            dashboard_config=dashboard_config,
            created_by=created_by,
            is_private=is_private,
        )
        session.add(dashboard)
        session.commit()
        session.refresh(dashboard)
        return dashboard


def delete_dashboard(tenant_id, dashboard_id):
    with Session(engine) as session:
        dashboard = session.exec(
            select(Dashboard)
            .where(Dashboard.tenant_id == tenant_id)
            .where(Dashboard.id == dashboard_id)
        ).first()
        if dashboard:
            session.delete(dashboard)
            session.commit()
            return True
        return False


def get_dashboards(tenant_id: str, email=None) -> List[Dict[str, Any]]:
    with Session(engine) as session:
        statement = (
            select(Dashboard)
            .where(Dashboard.tenant_id == tenant_id)
            .where(
                or_(
                    Dashboard.is_private == False,
                    Dashboard.created_by == email,
                )
            )
        )
        dashboards = session.exec(statement).all()
    # for postgres, the jsonb column is returned as a string
    # so we need to parse it
    for dashboard in dashboards:
        if isinstance(dashboard.dashboard_config, str):
            dashboard.dashboard_config = json.loads(dashboard.dashboard_config)
    return dashboards


def update_dashboard(
    tenant_id, dashboard_id, dashboard_name, dashboard_config, updated_by
):
    with Session(engine) as session:
        dashboard = session.exec(
            select(Dashboard)
            .where(Dashboard.tenant_id == tenant_id)
            .where(Dashboard.id == dashboard_id)
        ).first()
        if not dashboard:
            return None
        if dashboard_name:
            dashboard.dashboard_name = dashboard_name
        if dashboard_config:
            dashboard.dashboard_config = dashboard_config
        dashboard.updated_by = updated_by
        dashboard.updated_at = datetime.utcnow()
        session.commit()
        session.refresh(dashboard)
        return dashboard
