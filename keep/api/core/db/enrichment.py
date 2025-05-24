"""Database operations for enrichment."""

from typing import List, Optional

from retry import retry
from sqlalchemy import select, update
from sqlmodel import Session, select

from keep.api.core.db._common import Session, engine, logger, existed_or_new_session
from keep.api.models.action_type import ActionType
from keep.api.models.db.alert import AlertAudit, AlertEnrichment
from keep.api.models.db.enrichment_event import *
from sqlalchemy.exc import IntegrityError


def batch_enrich(
    tenant_id,
    fingerprints,
    enrichments,
    action_type: ActionType,
    action_callee: str,
    action_description: str,
    session=None,
    audit_enabled=True,
):
    """
    Batch enrich multiple alerts with the same enrichments in a single transaction.
    Args:
        tenant_id (str): The tenant ID to filter the alert enrichments by.
        fingerprints (List[str]): List of alert fingerprints to enrich.
        enrichments (dict): The enrichments to add to all alerts.
        action_type (ActionType): The type of action being performed.
        action_callee (str): The ID of the user performing the action.
        action_description (str): Description of the action.
        session (Session, optional): Database session to use.
        force (bool, optional): Whether to override existing enrichments. Defaults to False.
        audit_enabled (bool, optional): Whether to create audit entries. Defaults to True.
    Returns:
        List[AlertEnrichment]: List of enriched alert objects.
    """
    with existed_or_new_session(session) as session:
        # Get all existing enrichments in one query
        existing_enrichments = {
            e.alert_fingerprint: e
            for e in session.exec(
                select(AlertEnrichment)
                .where(AlertEnrichment.tenant_id == tenant_id)
                .where(AlertEnrichment.alert_fingerprint.in_(fingerprints))
            ).all()
        }
        # Prepare bulk update for existing enrichments
        to_update = []
        to_create = []
        audit_entries = []
        for fingerprint in fingerprints:
            existing = existing_enrichments.get(fingerprint)
            if existing:
                to_update.append(existing.id)
            else:
                # For new entries
                to_create.append(
                    AlertEnrichment(
                        tenant_id=tenant_id,
                        alert_fingerprint=fingerprint,
                        enrichments=enrichments,
                    )
                )
            if audit_enabled:
                audit_entries.append(
                    AlertAudit(
                        tenant_id=tenant_id,
                        fingerprint=fingerprint,
                        user_id=action_callee,
                        action=action_type.value,
                        description=action_description,
                    )
                )
        # Bulk update in a single query
        if to_update:
            stmt = (
                update(AlertEnrichment)
                .where(AlertEnrichment.id.in_(to_update))
                .values(enrichments=enrichments)
            )
            session.execute(stmt)
        # Bulk insert new enrichments
        if to_create:
            session.add_all(to_create)
        # Bulk insert audit entries
        if audit_entries:
            session.add_all(audit_entries)
        session.commit()
        # Get all updated/created enrichments
        result = session.exec(
            select(AlertEnrichment)
            .where(AlertEnrichment.tenant_id == tenant_id)
            .where(AlertEnrichment.alert_fingerprint.in_(fingerprints))
        ).all()
        return result


def get_enrichment(tenant_id, fingerprint, refresh=False):
    with Session(engine) as session:
        return get_enrichment_with_session(session, tenant_id, fingerprint, refresh)


@retry(exceptions=(Exception,), tries=3, delay=0.1, backoff=2)
def get_enrichment_with_session(session, tenant_id, fingerprint, refresh=False):
    try:
        alert_enrichment = session.exec(
            select(AlertEnrichment)
            .where(AlertEnrichment.tenant_id == tenant_id)
            .where(AlertEnrichment.alert_fingerprint == fingerprint)
        ).first()
        if refresh and alert_enrichment:
            try:
                session.refresh(alert_enrichment)
            except Exception:
                logger.exception(
                    "Failed to refresh enrichment",
                    extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
                )
                session.rollback()
                raise  # This will trigger a retry
        return alert_enrichment
    except Exception as e:
        if "PendingRollbackError" in str(e):
            logger.warning(
                "Session has pending rollback, attempting recovery",
                extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
            )
            session.rollback()
            raise  # This will trigger a retry
        else:
            logger.exception(
                "Unexpected error getting enrichment",
                extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
            )
            raise  # This will trigger a retry


def get_enrichments(
    tenant_id: int, fingerprints: List[str]
) -> List[Optional[AlertEnrichment]]:
    """
    Get a list of alert enrichments for a list of fingerprints using a single DB query.
    :param tenant_id: The tenant ID to filter the alert enrichments by.
    :param fingerprints: A list of fingerprints to get the alert enrichments for.
    :return: A list of AlertEnrichment objects or None for each fingerprint.
    """
    with Session(engine) as session:
        result = session.exec(
            select(AlertEnrichment)
            .where(AlertEnrichment.tenant_id == tenant_id)
            .where(AlertEnrichment.alert_fingerprint.in_(fingerprints))
        ).all()
    return result


def _enrich_entity(
    session,
    tenant_id,
    fingerprint,
    enrichments,
    action_type: ActionType,
    action_callee: str,
    action_description: str,
    force=False,
    audit_enabled=True,
):
    """
    Enrich an alert with the provided enrichments.
    Args:
        session (Session): The database session.
        tenant_id (str): The tenant ID to filter the alert enrichments by.
        fingerprint (str): The alert fingerprint to filter the alert enrichments by.
        enrichments (dict): The enrichments to add to the alert.
        force (bool): Whether to force the enrichment to be updated. This is used to dispose enrichments if necessary.
    """
    enrichment = get_enrichment_with_session(session, tenant_id, fingerprint)
    if enrichment:
        # if force - override exisitng enrichments. being used to dispose enrichments if necessary
        if force:
            new_enrichment_data = enrichments
        else:
            new_enrichment_data = {**enrichment.enrichments, **enrichments}
        # SQLAlchemy doesn't support updating JSON fields, so we need to do it manually
        # https://github.com/sqlalchemy/sqlalchemy/discussions/8396#discussion-4308891
        stmt = (
            update(AlertEnrichment)
            .where(AlertEnrichment.id == enrichment.id)
            .values(enrichments=new_enrichment_data)
        )
        session.execute(stmt)
        if audit_enabled:
            # add audit event
            audit = AlertAudit(
                tenant_id=tenant_id,
                fingerprint=fingerprint,
                user_id=action_callee,
                action=action_type.value,
                description=action_description,
            )
            session.add(audit)
        session.commit()
        # Refresh the instance to get updated data from the database
        session.refresh(enrichment)
        return enrichment
    else:
        try:
            alert_enrichment = AlertEnrichment(
                tenant_id=tenant_id,
                alert_fingerprint=fingerprint,
                enrichments=enrichments,
            )
            session.add(alert_enrichment)
            # add audit event
            if audit_enabled:
                audit = AlertAudit(
                    tenant_id=tenant_id,
                    fingerprint=fingerprint,
                    user_id=action_callee,
                    action=action_type.value,
                    description=action_description,
                )
                session.add(audit)
            session.commit()
            return alert_enrichment
        except IntegrityError:
            # If we hit a duplicate entry error, rollback and get the existing enrichment
            logger.warning(
                "Duplicate entry error",
                extra={
                    "tenant_id": tenant_id,
                    "fingerprint": fingerprint,
                    "enrichments": enrichments,
                },
            )
            session.rollback()
            return get_enrichment_with_session(session, tenant_id, fingerprint)


def enrich_entity(
    tenant_id,
    fingerprint,
    enrichments,
    action_type: ActionType,
    action_callee: str,
    action_description: str,
    session=None,
    force=False,
    audit_enabled=True,
):
    with existed_or_new_session(session) as session:
        return _enrich_entity(
            session,
            tenant_id,
            fingerprint,
            enrichments,
            action_type,
            action_callee,
            action_description,
            force=force,
            audit_enabled=audit_enabled,
        )
