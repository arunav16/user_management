from builtins import any, bool, str, ValueError
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import re
import uuid

from pydantic import BaseModel, EmailStr, Field, validator, root_validator

from app.models.user_model import UserRole
from app.utils.nickname_gen import generate_nickname


def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url


class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname()
    )
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(
        None, example="Experienced software developer specializing in web applications."
    )
    profile_picture_url: Optional[str] = Field(
        None, example="https://example.com/profiles/john.jpg"
    )
    linkedin_profile_url: Optional[str] = Field(
        None, example="https://linkedin.com/in/johndoe"
    )
    github_profile_url: Optional[str] = Field(
        None, example="https://github.com/johndoe"
    )
    role: UserRole

    _validate_urls = validator(
        'profile_picture_url', 'linkedin_profile_url', 'github_profile_url',
        pre=True, allow_reuse=True
    )(validate_url)

    class Config:
        from_attributes = True


class UserCreate(UserBase):
    password: str = Field(..., example="Secure*1234")


class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None, min_length=3, pattern=r'^[\w-]+$', example="john_doe123"
    )
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(
        None, example="Experienced software developer specializing in web applications."
    )
    profile_picture_url: Optional[str] = Field(
        None, example="https://example.com/profiles/john.jpg"
    )
    linkedin_profile_url: Optional[str] = Field(
        None, example="https://linkedin.com/in/johndoe"
    )
    github_profile_url: Optional[str] = Field(
        None, example="https://github.com/johndoe"
    )
    role: Optional[str] = Field(None, example="AUTHENTICATED")

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values


class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(
        None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname()
    )
    is_professional: Optional[bool] = Field(default=False, example=True)
    role: UserRole
    links: List[Dict[str, Any]] = Field(
        default_factory=list,
        example=[{"rel": "self", "href": "https://api.example.com/users/123"}]
    )

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(),
        "nickname": generate_nickname(),
        "email": "john.doe@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "bio": "Experienced developer",
        "role": "AUTHENTICATED",
        "profile_picture_url": "https://example.com/profiles/john.jpg",
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe",
        "is_professional": False,
        "links": [{"rel": "self", "href": "https://api.example.com/users/123"}]
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
    links: List[Dict[str, Any]] = Field(
        default_factory=list,
        example=[{"rel": "next", "href": "https://api.example.com/users?page=2"}]
    )


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")
