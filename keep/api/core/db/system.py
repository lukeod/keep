"""Database operations for system."""

from uuid import uuid4

from typing import Optional

from sqlalchemy import select
from sqlmodel import Session, select

from keep.api.core.db._common import Session, engine
from keep.api.models.db.system import *


def get_or_creat_posthog_instance_id(session: Optional[Session] = None):
    POSTHOG_INSTANCE_ID_KEY = "posthog_instance_id"
    with Session(engine) as session:
        system = session.exec(
            select(System).where(System.name == POSTHOG_INSTANCE_ID_KEY)
        ).first()
        if system:
            return system.value
        system = System(
            id=str(uuid4()),
            name=POSTHOG_INSTANCE_ID_KEY,
            value=str(uuid4()),
        )
        session.add(system)
        session.commit()
        session.refresh(system)
        return system.value
