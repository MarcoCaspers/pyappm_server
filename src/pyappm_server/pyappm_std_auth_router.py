# -*- coding: utf-8 -*-
#
# Product:   pyappm server
# Author:    Marco Caspers
# Email:     marco@0xc007.nl
# License:   MIT License
# Date:      2024-07-29
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

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordRequestForm

from datetime import datetime, timedelta, timezone


import pyappm_server_config
from pyappm_server_config import API_VERSION_PATH

from schemas import Token

from pyappm_auth_tools import __create_access_token__
from pyappm_auth_tools import ACCESS_TOKEN_EXPIRE_MINUTES_SHORT
from pyappm_auth_tools import ACCESS_TOKEN_EXPIRE_MINUTES
from pyappm_auth_tools import __get_current_user__
from pyappm_auth_tools import blacklist_token
from pyappm_auth_tools import __hash_password__

from schemas import UserEntity
from schemas import RegisterUserSchema
from schemas import UserToRegisterSchema
from schemas import RegisterResponseModel
from schemas import MessageResponseModel


router = APIRouter()


async def _login(payload: OAuth2PasswordRequestForm = Depends()) -> Token:
    if payload.username is None or payload.password is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not found",
        )
    user = await pyappm_server_config.database.find_async("email", payload.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES_SHORT)
    access_token = __create_access_token__(
        data={"sub": user.email, "otp_valid": False}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


# this is the endpoint to make swagger work.
@router.post("/token", response_model=Token)
async def token(payload: OAuth2PasswordRequestForm = Depends()) -> Token:
    return await _login(payload)


# this is the endpoint that users should use to login.
@router.post(f"{API_VERSION_PATH}/login", response_model=Token)
async def login(payload: OAuth2PasswordRequestForm = Depends()) -> Token:
    return await _login(payload)


@router.get(f"{API_VERSION_PATH}/logout")
async def logout(
    user: UserEntity = Depends(__get_current_user__),
) -> MessageResponseModel:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found",
        )
    if user.otp_valid is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not authorized",
        )
    if user.token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token not found",
        )
    blacklist_token(user.token, ACCESS_TOKEN_EXPIRE_MINUTES)
    return MessageResponseModel(message="Successfully logged out")


@router.post(
    f"{API_VERSION_PATH}/register",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponseModel,
)
async def create_user(payload: RegisterUserSchema) -> RegisterResponseModel:
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not found",
        )
    if pyappm_server_config.database.find_user_by_email(payload.email.lower()):
        raise HTTPException(status_code=400, detail="Account already exists")
    if payload.password_confirm != payload.password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    payload.email = payload.email.lower()
    payload.created_at = datetime.now(timezone.utc)
    payload.updated_at = datetime.now(timezone.utc)
    payload.password = __hash_password__(payload.password).decode("utf-8")
    user = UserToRegisterSchema(**payload.model_dump())
    pyappm_server_config.database.create_user(user)
    return RegisterResponseModel(
        status="success", message="Registered successfully, please login"
    )
