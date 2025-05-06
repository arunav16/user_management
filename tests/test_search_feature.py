# tests/test_user_service_search_filter.py

import pytest
from datetime import datetime, date, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.user_service import UserService
from app.models.user_model import User, UserRole
from app.utils.security import hash_password

pytestmark = pytest.mark.asyncio  # enable asyncio for all tests in this module

async def seed_users(session: AsyncSession):
    """
    Create two users in the test DB:
    - alice: created 10 days ago, role=AUTHENTICATED, is_professional=False
    - bob: created today,   role=MANAGER,       is_professional=True
    """
    now = datetime.utcnow()
    alice = User(
        email="alice@example.com",
        nickname="alice",
        hashed_password=hash_password("pw"),
        role=UserRole.AUTHENTICATED,
        is_professional=False,
    )
    bob = User(
        email="bob@example.com",
        nickname="bob",
        hashed_password=hash_password("pw"),
        role=UserRole.MANAGER,
        is_professional=True,
    )
    # override created_at for date‐range testing
    alice.created_at = now - timedelta(days=10)
    bob.created_at   = now

    session.add_all([alice, bob])
    await session.commit()
    # refresh so .created_at is recognized
    await session.refresh(alice)
    await session.refresh(bob)
    return alice, bob

async def test_search_by_nickname_and_email(db_session: AsyncSession):
    alice, bob = await seed_users(db_session)

    # search by partial nickname (case‐insensitive)
    results = await UserService.search_users(db_session, search="Ali")
    assert len(results) == 1
    assert results[0].email == "alice@example.com"

    # search by partial email
    results = await UserService.search_users(db_session, search="bob@")
    assert len(results) == 1
    assert results[0].nickname == "bob"

async def test_filter_by_role(db_session: AsyncSession):
    alice, bob = await seed_users(db_session)

    # only MANAGER should come back
    results = await UserService.search_users(db_session, role=UserRole.MANAGER)
    assert len(results) == 1
    assert results[0].nickname == "bob"

async def test_filter_by_professional_status(db_session: AsyncSession):
    alice, bob = await seed_users(db_session)

    # only the professional user
    results = await UserService.search_users(db_session, is_professional=True)
    assert len(results) == 1
    assert results[0].nickname == "bob"

async def test_registration_date_range(db_session: AsyncSession):
    alice, bob = await seed_users(db_session)

    # from “today” on, only bob should show
    results = await UserService.search_users(
        db_session,
        registered_from=date.today()
    )
    assert len(results) == 1
    assert results[0].nickname == "bob"

async def test_count_users_filtered(db_session: AsyncSession):
    alice, bob = await seed_users(db_session)

    count_auth = await UserService.count_users_filtered(
        db_session, role=UserRole.AUTHENTICATED
    )
    assert count_auth == 1

    count_prof = await UserService.count_users_filtered(
        db_session, is_professional=True
    )
    assert count_prof == 1
