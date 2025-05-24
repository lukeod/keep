"""Database operations for ai."""

import json
import os

from typing import List

from sqlalchemy import select
from sqlmodel import Session, select

from keep.api.core.db._common import Session, engine
from keep.api.models.ai_external import (
    ExternalAIConfigAndMetadata,
    ExternalAIConfigAndMetadataDto,
)
from keep.api.models.db.ai_external import *
from keep.api.models.db.ai_external import external_ai_transformers


def get_or_create_external_ai_settings(
    tenant_id: str,
) -> List[ExternalAIConfigAndMetadataDto]:
    with Session(engine) as session:
        algorithm_configs = session.exec(
            select(ExternalAIConfigAndMetadata).where(
                ExternalAIConfigAndMetadata.tenant_id == tenant_id
            )
        ).all()
        if len(algorithm_configs) == 0:
            if os.environ.get("KEEP_EXTERNAL_AI_TRANSFORMERS_URL") is not None:
                algorithm_config = ExternalAIConfigAndMetadata.from_external_ai(
                    tenant_id=tenant_id, algorithm=external_ai_transformers
                )
                session.add(algorithm_config)
                session.commit()
                algorithm_configs = [algorithm_config]
        return [
            ExternalAIConfigAndMetadataDto.from_orm(algorithm_config)
            for algorithm_config in algorithm_configs
        ]


def update_extrnal_ai_settings(
    tenant_id: str, ai_settings: ExternalAIConfigAndMetadata
) -> ExternalAIConfigAndMetadataDto:
    with Session(engine) as session:
        setting = (
            session.query(ExternalAIConfigAndMetadata)
            .filter(
                ExternalAIConfigAndMetadata.tenant_id == tenant_id,
                ExternalAIConfigAndMetadata.id == ai_settings.id,
            )
            .first()
        )
        setting.settings = json.dumps(ai_settings.settings)
        setting.feedback_logs = ai_settings.feedback_logs
        if ai_settings.settings_proposed_by_algorithm is not None:
            setting.settings_proposed_by_algorithm = json.dumps(
                ai_settings.settings_proposed_by_algorithm
            )
        else:
            setting.settings_proposed_by_algorithm = None
        session.add(setting)
        session.commit()
    return setting
