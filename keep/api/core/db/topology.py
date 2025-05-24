"""Database operations for topology."""

from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlmodel import Session, select

from keep.api.core.db._common import Session, engine
from keep.api.models.db.topology import *


def get_topology_data_by_dynamic_matcher(
    tenant_id: str, matchers_value: dict[str, str]
) -> TopologyService | None:
    with Session(engine) as session:
        query = select(TopologyService).where(TopologyService.tenant_id == tenant_id)
        for matcher in matchers_value:
            query = query.where(
                getattr(TopologyService, matcher) == matchers_value[matcher]
            )
        # Add joinedload for applications to avoid detached instance error
        query = query.options(joinedload(TopologyService.applications))
        service = session.exec(query).first()
        return service
