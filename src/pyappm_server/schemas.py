# -*- coding: utf-8 -*-
#
# Product:   pyappm server
# Author:    Marco Caspers
# Email:     marco@0xc007.nl
# License:   MIT License
# Date:      2024-06-25
#
# Copyright 2024 Marco Caspers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# SPDX-License-Identifier: MIT
#

from datetime import datetime
from pydantic import BaseModel
from pydantic import EmailStr
from pydantic import Field
from fastapi import Body
from typing_extensions import Annotated
from typing import Any
from pathlib import Path


class UserBaseSchema(BaseModel):
    name: str
    email: str

    otp_enabled: bool = False
    otp_verified: bool = False

    otp_base32: str | None = None
    otp_auth_url: str | None = None

    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class UserToRegisterSchema(UserBaseSchema):
    password: str


class RegisterUserSchema(UserBaseSchema):
    password: Annotated[
        str,
        Field(
            min_length=8,
            max_length=128,
            example="password",
            title="Password",
            description="Password",
            type="password",
        ),
    ]
    password_confirm: Annotated[
        str,
        Field(
            min_length=8,
            max_length=128,
            title="Password confirmation",
            example="password",
            description="Password confirmation",
            type="password",
        ),
    ]


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: Annotated[
        str,
        Body(
            min_length=8,
            max_length=128,
            example="password",
            title="Password",
            description="Password",
            type="password",
        ),
    ]


class UserRequestSchema(BaseModel):
    user_id: str
    token: str | None = None


class MessageResponseModel(BaseModel):
    message: str


class RegisterResponseModel(BaseModel):
    status: str
    message: str


class UserEntity(BaseModel):
    id: int
    name: str
    email: str
    hash: bytes
    otp_enabled: bool
    otp_verified: bool
    otp_base32: str | None
    otp_auth_url: str | None
    created_at: datetime
    updated_at: datetime
    otp_valid: bool = False
    token: str | None = None


class SaferUserEntity(BaseModel):
    id: int
    name: str
    email: str
    otp_enabled: bool
    otp_verified: bool
    created_at: datetime
    updated_at: datetime


class OTPResponseModel(BaseModel):
    base32: str
    otpauth_url: str


class VerifyResponseModel(BaseModel):
    otp_verified: bool
    user: UserEntity


class ValidateResponseModel(BaseModel):
    otp_valid: bool
    access_token: str
    token_type: str


class DisableResponseModel(BaseModel):
    otp_disabled: bool
    user: UserEntity


UsersResponseModel = list[SaferUserEntity]


class Token(BaseModel):
    access_token: str
    token_type: str


class LoginRequestModel(BaseModel):
    email: str
    password: str
    otp_code: str | None = None


class ApplicationSchema(BaseModel):
    id: int | None = None  # application db table primary key, None for new applications
    owner_id: int  # reference to the user that manages/maintains the application
    name: str  # name of the application
    type: str  # type of the application (application or service)
    version: str  # version of the application
    description: str | None = None  # description (optional)
    created_at: datetime | None = None  # creation date, None for new applications
    updated_at: datetime | None = None  # last update date, None for new applications
    sha_256: str | None = None  # sha256 hash of the file, None if not uploading.


class ApplicationAuthorSchema(BaseModel):
    id: int  # author ID
    app_id: int  # application ID
    name: str  # name of the author
    email: str  # email of the author
    created_at: datetime
    updated_at: datetime


class Settings(BaseModel):
    app_name: str
    db_file_path: Path
    # default client origin for protecting against CSRF attacks
    client_origin: str = "http://localhost:8000"
    upload_path: Path = Path("uploads")

    class Config:
        env_file: str = ".env"
        env_file_encoding: str = "utf-8"
        case_sensitive: bool = True


AppsResponseModel = list[ApplicationSchema]
AuthorsResponseModel = list[ApplicationAuthorSchema]


class FileResponseModel(BaseModel):
    file_name: str
    file_size: int
    file_type: str
    file_sha256: str
    file: bytes
    app_type: str
    app_version: str
    description: str
    created_at: datetime
    updated_at: datetime


FilesResponseModel = list[FileResponseModel]
