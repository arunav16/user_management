from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app
from datetime import datetime, timedelta
from urllib.parse import urlencode
from fastapi import status
from app.models.user_model import UserRole
from app.services.jwt_service import decode_token


# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user


####
@pytest.mark.asyncio
async def test_verify_email_invalid_token(async_client, unverified_user):
    user_id = str(unverified_user.id)
    bad_token = "not-a-real-token"
    resp = await async_client.get(f"/verify-email/{user_id}/{bad_token}")
    assert resp.status_code == 400
    assert "Invalid or expired verification token" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_list_users_search_by_email(async_client, admin_token, db_session):
    # Ensure there's a user with a known email fragment
    from app.models.user_model import User
    u = User(
        email="findme123@example.com",
        nickname="finder",
        hashed_password="x",
        role=UserRole.AUTHENTICATED,
    )
    db_session.add(u)
    await db_session.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}
    params = {"search": "findme123"}
    resp = await async_client.get("/users/?" + urlencode(params), headers=headers)
    assert resp.status_code == 200

    items = resp.json()["items"]
    assert any(item["email"] == "findme123@example.com" for item in items)

@pytest.mark.asyncio
async def test_list_users_filter_by_role_and_professional(async_client, admin_token, db_session):
    from app.models.user_model import User
    # Create a professional manager and an anonymous non-professional
    prof = User(email="pro@example.com", nickname="pro", hashed_password="x",
                role=UserRole.MANAGER, is_professional=True)
    anon = User(email="anon@example.com", nickname="anon", hashed_password="x",
                role=UserRole.ANONYMOUS, is_professional=False)
    db_session.add_all([prof, anon])
    await db_session.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}
    params = {"role": "MANAGER", "is_professional": "true"}
    resp = await async_client.get("/users/?" + urlencode(params), headers=headers)
    assert resp.status_code == 200

    items = resp.json()["items"]
    assert all(item["role"] == "MANAGER" and item["is_professional"] for item in items)

@pytest.mark.asyncio
async def test_list_users_date_range_and_sort(async_client, admin_token, db_session):
    from app.models.user_model import User
    # Create two users with distinct created_at
    older = User(
        email="old@example.com", nickname="old", hashed_password="x",
        role=UserRole.AUTHENTICATED, created_at=datetime.utcnow() - timedelta(days=10)
    )
    newer = User(
        email="new@example.com", nickname="new", hashed_password="x",
        role=UserRole.AUTHENTICATED, created_at=datetime.utcnow() - timedelta(days=1)
    )
    db_session.add_all([older, newer])
    await db_session.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}
    # Filter for last week, sort ascending by created_at
    from_date = (datetime.utcnow() - timedelta(days=7)).date().isoformat()
    params = {"registered_from": from_date, "sort_by": "created_at", "sort_order": "asc"}
    resp = await async_client.get("/users/?" + urlencode(params), headers=headers)
    assert resp.status_code == 200

    items = resp.json()["items"]
    # Only 'new' should appear
    emails = [i["email"] for i in items]
    assert "new@example.com" in emails
    assert "old@example.com" not in emails

@pytest.mark.asyncio
async def test_list_users_pagination(async_client, admin_token, db_session):
    # ensure at least 3 users in DB
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp1 = await async_client.get("/users/?page=1&size=2", headers=headers)
    resp2 = await async_client.get("/users/?page=2&size=2", headers=headers)
    assert resp1.status_code == resp2.status_code == 200

    # page 1 and page 2 should not have identical item sets
    items1 = {u["email"] for u in resp1.json()["items"]}
    items2 = {u["email"] for u in resp2.json()["items"]}
    assert items1 != items2


@pytest.mark.asyncio
async def test_list_users_invalid_page_size(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # size too large (over 100)
    resp = await async_client.get("/users/?size=101", headers=headers)
    assert resp.status_code == 422

@pytest.mark.asyncio
async def test_list_users_bad_date_format(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await async_client.get("/users/?registered_from=not-a-date", headers=headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_protected_endpoints_require_auth(async_client):
    # Try GET /users/ without token
    resp = await async_client.get("/users/")
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    # Try POST /users/
    resp = await async_client.post("/users/", json={})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    # Try PUT /users/<uuid>
    resp = await async_client.put("/users/00000000-0000-0000-0000-000000000000", json={})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    # Try DELETE /users/<uuid>
    resp = await async_client.delete("/users/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ─── Invalid UUID in path ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_user_invalid_uuid(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # missing hyphens etc
    resp = await async_client.get("/users/not-a-uuid", headers=headers)
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

@pytest.mark.asyncio
async def test_delete_user_invalid_uuid(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await async_client.delete("/users/not-a-uuid", headers=headers)
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ─── Create / Register payload validation ──────────────────────────────────

@pytest.mark.asyncio
async def test_create_user_missing_fields(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # omit email & password
    resp = await async_client.post("/users/", json={"nickname": "short"}, headers=headers)
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

@pytest.mark.asyncio
async def test_register_missing_email_or_password(async_client):
    # missing password
    resp = await async_client.post("/register/", json={"email": "a@b.com"})
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # missing email
    resp = await async_client.post("/register/", json={"password": "Xyz#1234"})
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

@pytest.mark.asyncio
async def test_register_invalid_nickname_pattern(async_client):
    # nickname too short / invalid chars
    payload = {"email":"x@y.com","password":"Abc#1234","nickname":"!!"}
    resp = await async_client.post("/register/", json=payload)
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ─── Update / Delete edge-cases ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_user_not_found(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await async_client.put(
        "/users/00000000-0000-0000-0000-000000000000",
        json={"bio":"does not exist"},
        headers=headers
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND

@pytest.mark.asyncio
async def test_delete_user_unauthorized_role(async_client, manager_token):
    headers = {"Authorization": f"Bearer {manager_token}"}
    # Managers are allowed to delete, but let's test a normal user:
    # we need user_token fixture for an authenticated user:
    user_token = manager_token.replace("MANAGER", "AUTHENTICATED")
    headers_user = {"Authorization": f"Bearer {user_token}"}
    resp = await async_client.delete("/users/00000000-0000-0000-0000-000000000000", headers=headers_user)
    assert resp.status_code == status.HTTP_403_FORBIDDEN


# ─── Login edge-cases ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_missing_form_fields(async_client):
    # no username nor password
    resp = await async_client.post("/login/", data="")
    assert resp.status_code in (status.HTTP_422_UNPROCESSABLE_ENTITY, status.HTTP_400_BAD_REQUEST)

@pytest.mark.asyncio
async def test_login_token_contains_expiry(async_client, verified_user):
    form = {"username": verified_user.email, "password":"MySuperPassword$1234"}
    resp = await async_client.post(
        "/login/",
        data=urlencode(form),
        headers={"Content-Type":"application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    payload = decode_token(token)
    # exp should be > now
    assert payload["exp"] > datetime.utcnow().timestamp()


# ─── List / Filtering edge-cases ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_users_bad_role_value(async_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = await async_client.get("/users/?role=NOTAROLE", headers=headers)
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ─── Verify-email malformed inputs ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_email_bad_uuid(async_client):
    resp = await async_client.get("/verify-email/not-a-uuid/sometoken")
    assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
