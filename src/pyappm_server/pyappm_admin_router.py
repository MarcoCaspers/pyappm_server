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

from fastapi import APIRouter, HTTPException, status  # type: ignore

from schemas import UsersResponseModel
from schemas import UserEntity
from schemas import SaferUserEntity
from schemas import AppsResponseModel
from schemas import AuthorsResponseModel


from fastapi import Depends

from pyappm_auth_tools import __get_current_user__
from pyappm_auth_tools import is_token_blacklisted

import pyappm_server_config

router = APIRouter()


@router.get("/users", response_model=UsersResponseModel)
async def read_users(
    user: UserEntity = Depends(__get_current_user__),
) -> UsersResponseModel:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found",
        )
    if is_token_blacklisted(str(user.token)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is blacklisted",
        )
    if user.otp_valid is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login with 2FA is required",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not available",
        )
    users = await pyappm_server_config.database.read_users_async()
    return users


@router.get("/users/{user_id}", response_model=SaferUserEntity)
async def read_user(
    user_id: int,
    user: UserEntity = Depends(__get_current_user__),
) -> SaferUserEntity:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found",
        )
    if is_token_blacklisted(str(user.token)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is blacklisted",
        )
    if user.otp_valid is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login with 2FA is required",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not available",
        )
    find_user = await pyappm_server_config.database.read_user_async(user_id)
    if find_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return find_user


@router.get("/users/{user_id}/apps", response_model=AppsResponseModel)
async def read_user_apps(
    user_id: int,
    user: UserEntity = Depends(__get_current_user__),
) -> AppsResponseModel:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found",
        )
    if is_token_blacklisted(str(user.token)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is blacklisted",
        )
    if user.otp_valid is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login with 2FA is required",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not available",
        )
    apps = await pyappm_server_config.database.read_apps_by_owner_id_async(user_id)
    return apps


@router.get("/authors/list", response_model=AuthorsResponseModel)
async def read_authors(
    user: UserEntity = Depends(__get_current_user__),
) -> AuthorsResponseModel:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found",
        )
    if is_token_blacklisted(str(user.token)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is blacklisted",
        )
    if user.otp_valid is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login with 2FA is required",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not available",
        )
    authors = await pyappm_server_config.database.read_authors_async()
    return authors
