from uuid import UUID
from datetime import timedelta, date
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status, Request, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_email_service, require_role, get_settings
from app.models.user_model import UserRole
from app.schemas.user_schemas import UserCreate, UserUpdate, UserResponse, UserListResponse
from app.schemas.token_schema import TokenResponse
from app.services.user_service import UserService
from app.services.jwt_service import create_access_token
from app.services.email_service import EmailService
from app.utils.link_generation import create_user_links, generate_pagination_links

settings = get_settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ── CRUD routes under /users ──────────────────────────────────────────────────

router = APIRouter(prefix="/users", tags=["User Management Requires (Admin or Manager Roles)"])


@router.post(
    "/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    name="create_user",
)
async def create_user(
    user_in: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
    token: str = Depends(oauth2_scheme),
    current_user=Depends(require_role(["ADMIN", "MANAGER"])),
):
    # Prevent duplicates
    if await UserService.get_by_email(db, user_in.email):
        raise HTTPException(status_code=400, detail="Email already exists")

    created = await UserService.create(db, user_in.model_dump(), email_service)
    if not created:
        raise HTTPException(status_code=500, detail="Failed to create user")

    resp = UserResponse.model_validate(created)
    resp.links = create_user_links(created.id, request)
    return resp


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    name="get_user",
)
async def get_user(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user=Depends(require_role(["ADMIN", "MANAGER"])),
):
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    resp = UserResponse.model_validate(user)
    resp.links = create_user_links(user.id, request)
    return resp


@router.put(
    "/{user_id}",
    response_model=UserResponse,
    name="update_user",
)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user=Depends(require_role(["ADMIN", "MANAGER"])),
):
    data = user_update.model_dump(exclude_unset=True)
    updated = await UserService.update(db, user_id, data)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")

    resp = UserResponse.model_validate(updated)
    resp.links = create_user_links(updated.id, request)
    return resp


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    name="delete_user",
)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user=Depends(require_role(["ADMIN"])),
):
    if not await UserService.delete(db, user_id):
        raise HTTPException(status_code=404, detail="User not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/",
    response_model=UserListResponse,
    name="list_users",
)
async def list_users(
    request: Request,
    search: Optional[str] = Query(None, description="username or email substring"),
    role: Optional[UserRole] = Query(None, description="Filter by role"),
    is_professional: Optional[bool] = Query(None, description="Filter by professional status"),
    registered_from: Optional[date] = Query(None, description="Registration date ≥ this date"),
    registered_to: Optional[date] = Query(None, description="Registration date ≤ this date"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(10, ge=1, le=100, description="Items per page"),
    sort_by: str = Query("created_at", description="Field to sort by"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort direction"),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role(["ADMIN", "MANAGER"])),
):
    offset = (page - 1) * size

    users = await UserService.search_users(
        session=db,
        search=search,
        role=role,
        is_professional=is_professional,
        registered_from=registered_from,
        registered_to=registered_to,
        offset=offset,
        limit=size,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    total = await UserService.count_users_filtered(
        session=db,
        search=search,
        role=role,
        is_professional=is_professional,
        registered_from=registered_from,
        registered_to=registered_to,
    )

    raw_links = generate_pagination_links(request, offset, size, total)
    links = [{"rel": link.rel, "href": link.href} for link in raw_links]

    return UserListResponse(
        items=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=page,
        size=len(users),
        links=links,
    )


# ── Auth routes (outside /users prefix) ────────────────────────────────────────

auth_router = APIRouter(tags=["Login and Registration"])


@auth_router.post("/register/", response_model=UserResponse, name="register")
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    user = await UserService.register_user(db, user_in.model_dump(), email_service)
    if not user:
        raise HTTPException(status_code=400, detail="Email already exists")
    return UserResponse.model_validate(user)


@auth_router.post("/login/", response_model=TokenResponse, name="login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    if await UserService.is_account_locked(db, form_data.username):
        raise HTTPException(status_code=400, detail="Account locked due to too many failed login attempts.")
    user = await UserService.login_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.email, "role": str(user.role.name)},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@auth_router.get("/verify-email/{user_id}/{token}", name="verify_email")
async def verify_email(
    user_id: UUID,
    token: str,
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    if not await UserService.verify_email_with_token(db, user_id, token):
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    return {"message": "Email verified successfully"}
