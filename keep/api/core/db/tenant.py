"""Database operations for tenant."""

from uuid import uuid4
from datetime import datetime as dt, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm.exc import StaleDataError
from sqlmodel import Session, select

from keep.api.core.db._common import Session, engine, logger
from keep.api.models.db.tenant import *


def create_single_tenant_for_e2e(tenant_id: str) -> None:
    """
    Creates the single tenant and the default user if they don't exist.
    """
    with Session(engine) as session:
        try:
            # check if the tenant exist:
            logger.info("Checking if single tenant exists")
            tenant = session.exec(select(Tenant).where(Tenant.id == tenant_id)).first()
            if not tenant:
                # Do everything related with single tenant creation in here
                logger.info("Creating single tenant", extra={"tenant_id": tenant_id})
                session.add(Tenant(id=tenant_id, name="Single Tenant"))
            else:
                logger.info("Single tenant already exists")
            # commit the changes
            session.commit()
            logger.info("Single tenant created", extra={"tenant_id": tenant_id})
        except IntegrityError:
            # Tenant already exists
            logger.exception("Failed to provision single tenant")
            raise
        except Exception:
            logger.exception("Failed to create single tenant")
            pass


def create_tenant(tenant_name: str) -> str:
    with Session(engine) as session:
        try:
            # check if the tenant exist:
            logger.info("Checking if tenant exists")
            tenant = session.exec(
                select(Tenant).where(Tenant.name == tenant_name)
            ).first()
            if not tenant:
                # Do everything related with single tenant creation in here
                tenant_id = str(uuid4())
                logger.info(
                    "Creating tenant",
                    extra={"tenant_id": tenant_id, "tenant_name": tenant_name},
                )
                session.add(Tenant(id=tenant_id, name=tenant_name))
            else:
                logger.warning("Tenant already exists")
            # commit the changes
            session.commit()
            logger.info(
                "Tenant created",
                extra={"tenant_id": tenant_id, "tenant_name": tenant_name},
            )
            return tenant_id
        except IntegrityError:
            # Tenant already exists
            logger.exception("Failed to create tenant")
            raise
        except Exception:
            logger.exception("Failed to create tenant")
            pass


def get_tenant_config(tenant_id: str) -> dict:
    with Session(engine) as session:
        tenant_data = session.exec(select(Tenant).where(Tenant.id == tenant_id)).first()
        return tenant_data.configuration if tenant_data else {}


def get_tenants():
    with Session(engine) as session:
        tenants = session.exec(select(Tenant)).all()
        return tenants


def get_tenants_configurations(only_with_config=False) -> dict:
    with Session(engine) as session:
        try:
            tenants = session.exec(select(Tenant)).all()
        # except column configuration does not exist (new column added)
        except OperationalError as e:
            if "Unknown column" in str(e):
                logger.warning("Column configuration does not exist in the database")
                return {}
            else:
                logger.exception("Failed to get tenants configurations")
                return {}
    tenants_configurations = {}
    for tenant in tenants:
        if only_with_config and not tenant.configuration:
            continue
        tenants_configurations[tenant.id] = tenant.configuration or {}
    return tenants_configurations


def write_tenant_config(tenant_id: str, config: dict) -> None:
    with Session(engine) as session:
        tenant_data = session.exec(select(Tenant).where(Tenant.id == tenant_id)).first()
        tenant_data.configuration = config
        session.commit()
        session.refresh(tenant_data)
        return tenant_data


def update_key_last_used(
    tenant_id: str,
    reference_id: str,
    max_retries=3,
) -> str:
    """
    Updates API key last used.
    Args:
        session (Session): _description_
        tenant_id (str): _description_
        reference_id (str): _description_
    Returns:
        str: _description_
    """
    with Session(engine) as session:
        # Get API Key from database
        statement = (
            select(TenantApiKey)
            .where(TenantApiKey.reference_id == reference_id)
            .where(TenantApiKey.tenant_id == tenant_id)
        )
        tenant_api_key_entry = session.exec(statement).first()
        # Update last used
        if not tenant_api_key_entry:
            # shouldn't happen but somehow happened to specific tenant so logging it
            logger.error(
                "API key not found",
                extra={"tenant_id": tenant_id, "unique_api_key_id": reference_id},
            )
            return
        tenant_api_key_entry.last_used = dt.now(tz=timezone.utc)
        for attempt in range(max_retries):
            try:
                session.add(tenant_api_key_entry)
                session.commit()
                break
            except StaleDataError as ex:
                if "expected to update" in ex.args[0]:
                    logger.info(
                        f"Phantom read detected while updating API key `{reference_id}`, retry #{attempt}"
                    )
                    session.rollback()
                    continue
                else:
                    raise
