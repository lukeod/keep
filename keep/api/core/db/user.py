"""Database operations for user."""

import hashlib
from datetime import datetime as dt, timezone

from sqlalchemy import select
from sqlmodel import Session, select

from keep.api.core.db._common import Session, engine
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.db.tenant import TenantApiKey
from keep.api.models.db.user import User


def create_user(tenant_id, username, password, role):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    with Session(engine) as session:
        user = User(
            tenant_id=tenant_id,
            username=username,
            password_hash=password_hash,
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


def delete_user(username):
    with Session(engine) as session:
        user = session.exec(
            select(User)
            .where(User.tenant_id == SINGLE_TENANT_UUID)
            .where(User.username == username)
        ).first()
        if user:
            session.delete(user)
            session.commit()


def get_api_key(api_key: str) -> TenantApiKey:
    with Session(engine) as session:
        api_key_hashed = hashlib.sha256(api_key.encode()).hexdigest()
        statement = select(TenantApiKey).where(TenantApiKey.key_hash == api_key_hashed)
        tenant_api_key = session.exec(statement).first()
    return tenant_api_key


# this is only for single tenant
def get_user(username, password, update_sign_in=True):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    with Session(engine, expire_on_commit=False) as session:
        user = session.exec(
            select(User)
            .where(User.tenant_id == SINGLE_TENANT_UUID)
            .where(User.username == username)
            .where(User.password_hash == password_hash)
        ).first()
        if user and update_sign_in:
            user.last_sign_in = dt.now(tz=timezone.utc)
            session.add(user)
            session.commit()
    return user


def get_user_by_api_key(api_key: str):
    api_key = get_api_key(api_key)
    return api_key.created_by


def get_users(tenant_id=None):
    tenant_id = tenant_id or SINGLE_TENANT_UUID
    with Session(engine) as session:
        users = session.exec(select(User).where(User.tenant_id == tenant_id)).all()
    return users


def update_user_last_sign_in(tenant_id, username):
    with Session(engine) as session:
        user = session.exec(
            select(User)
            .where(User.tenant_id == tenant_id)
            .where(User.username == username)
        ).first()
        if user:
            user.last_sign_in = dt.now(tz=timezone.utc)
            session.add(user)
            session.commit()
    return user


def update_user_role(tenant_id, username, role):
    with Session(engine) as session:
        user = session.exec(
            select(User)
            .where(User.tenant_id == tenant_id)
            .where(User.username == username)
        ).first()
        if user and user.role != role:
            user.role = role
            session.add(user)
            session.commit()
    return user


def user_exists(tenant_id, username):
    with Session(engine) as session:
        user = session.exec(
            select(User)
            .where(User.tenant_id == tenant_id)
            .where(User.username == username)
        ).first()
        return user is not None
