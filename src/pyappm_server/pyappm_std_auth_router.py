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


import config  # type: ignore
from config import API_VERSION_PATH  # type: ignore

from schemas import Token  # type: ignore

from pyappm_auth_tools import __create_access_token__  # type: ignore
from pyappm_auth_tools import ACCESS_TOKEN_EXPIRE_MINUTES_SHORT  # type: ignore
from pyappm_auth_tools import ACCESS_TOKEN_EXPIRE_MINUTES  # type: ignore
from pyappm_auth_tools import __get_current_user__  # type: ignore
from pyappm_auth_tools import blacklist_token  # type: ignore
from pyappm_auth_tools import __hash_password__  # type: ignore

from schemas import UserEntity  # type: ignore
from schemas import RegisterUserSchema  # type: ignore
from schemas import UserToRegisterSchema  # type: ignore
from schemas import RegisterResponseModel  # type: ignore


router = APIRouter()


# this is the endpoint to make swagger work.
@router.post("/token", response_model=Token)
async def token(payload: OAuth2PasswordRequestForm = Depends()):
    user = await config.database.find_async("email", payload.username)
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
    return {"access_token": access_token, "token_type": "bearer"}


# this is the endpoint that users should use to login.
@router.post(f"{API_VERSION_PATH}/login", response_model=Token)
async def login(payload: OAuth2PasswordRequestForm = Depends()):
    user = await config.database.find_async("email", payload.username)
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
    return {"access_token": access_token, "token_type": "bearer"}


@router.get(f"{API_VERSION_PATH}/logout")
async def logout(user: UserEntity = Depends(__get_current_user__)):
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
    blacklist_token(user.token, ACCESS_TOKEN_EXPIRE_MINUTES)
    return {"message": "Successfully logged out"}


@router.post(
    f"{API_VERSION_PATH}/register",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponseModel,
)
async def create_user(payload: RegisterUserSchema) -> RegisterResponseModel:
    if config.database.find_user_by_email(payload.email.lower()):
        raise HTTPException(status_code=400, detail="Account already exists")
    if payload.password_confirm != payload.password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    payload.email = payload.email.lower()
    payload.created_at = datetime.now(timezone.utc)
    payload.updated_at = datetime.now(timezone.utc)
    payload.password = __hash_password__(payload.password).decode("utf-8")
    user = UserToRegisterSchema(**payload.model_dump())
    config.database.create_user(user)
    return {"status": "success", "message": "Registered successfully, please login"}
