"""Database operations for preset."""

from typing import Any, Dict, List

from sqlalchemy import select, update
from sqlmodel import Session, or_, select

from keep.api.consts import STATIC_PRESETS
from keep.api.core.db._common import Session, engine, __convert_to_uuid
from keep.api.models.db.preset import *


def assign_tag_to_preset(tenant_id: str, tag_id: str, preset_id: str):
    if isinstance(preset_id, str):
        preset_id = __convert_to_uuid(preset_id)
    with Session(engine) as session:
        tag_preset = PresetTagLink(
            tenant_id=tenant_id,
            tag_id=tag_id,
            preset_id=preset_id,
        )
        session.add(tag_preset)
        session.commit()
        session.refresh(tag_preset)
        return tag_preset


def get_all_presets_dtos(tenant_id: str) -> List[PresetDto]:
    presets = get_db_presets(tenant_id)
    static_presets_dtos = list(STATIC_PRESETS.values())
    return [PresetDto(**preset.to_dict()) for preset in presets] + static_presets_dtos


def get_db_preset_by_name(tenant_id: str, preset_name: str) -> Preset | None:
    with Session(engine) as session:
        preset = session.exec(
            select(Preset)
            .where(Preset.tenant_id == tenant_id)
            .where(Preset.name == preset_name)
        ).first()
    return preset


def get_db_presets(tenant_id: str) -> List[Preset]:
    with Session(engine) as session:
        presets = (
            session.exec(select(Preset).where(Preset.tenant_id == tenant_id))
            .unique()
            .all()
        )
    return presets


def get_presets(
    tenant_id: str, email, preset_ids: list[str] = None
) -> List[Dict[str, Any]]:
    with Session(engine) as session:
        # v2 with RBAC and roles
        if preset_ids:
            statement = (
                select(Preset)
                .where(Preset.tenant_id == tenant_id)
                .where(Preset.id.in_(preset_ids))
            )
        # v1, no RBAC and roles
        else:
            statement = (
                select(Preset)
                .where(Preset.tenant_id == tenant_id)
                .where(
                    or_(
                        Preset.is_private == False,
                        Preset.created_by == email,
                    )
                )
            )
        result = session.exec(statement)
        presets = result.unique().all()
    return presets


def update_preset_options(tenant_id: str, preset_id: str, options: dict) -> Preset:
    if isinstance(preset_id, str):
        preset_id = __convert_to_uuid(preset_id)
    with Session(engine) as session:
        preset = session.exec(
            select(Preset)
            .where(Preset.tenant_id == tenant_id)
            .where(Preset.id == preset_id)
        ).first()
        stmt = (
            update(Preset)
            .where(Preset.id == preset_id)
            .where(Preset.tenant_id == tenant_id)
            .values(options=options)
        )
        session.execute(stmt)
        session.commit()
        session.refresh(preset)
    return preset


def create_tag(tag: Tag):
    with Session(engine) as session:
        session.add(tag)
        session.commit()
        session.refresh(tag)
        return tag


def get_tags(tenant_id):
    with Session(engine) as session:
        tags = session.exec(select(Tag).where(Tag.tenant_id == tenant_id)).all()
    return tags
