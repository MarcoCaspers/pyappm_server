# -*- coding: utf-8 -*-
#
# Product:   pyappm server
# Author:    Marco Caspers
# Email:     marco@0xc007.nl
# License:   MIT License
# Date:      2024-09-11
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

# Description:
#
# This module contains shared functions for the pyappm server application.
# This is to prevent circular imports.

import os

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from dotenv import load_dotenv

from jose import jwt  # type: ignore
from jose import JWTError  # type: ignore

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException
from fastapi import status

from passlib.context import CryptContext  # type: ignore

from schemas import UserEntity

import bcrypt  # type: ignore

import pyappm_server_config

ACCESS_TOKEN_EXPIRE_MINUTES_SHORT = 3
ACCESS_TOKEN_EXPIRE_MINUTES = 30

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

EX_ValidationError = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid username or password",
    headers={"WWW-Authenticate": "Bearer"},
)

token_blacklist: dict[str, datetime] = {}


def blacklist_token(token: str, minutes: int) -> None:
    token_blacklist[token] = datetime.now(timezone.utc) + timedelta(minutes=minutes)


def validate_token(token: str) -> bool:
    return not (token in token_blacklist)


def cleanup_blacklist() -> None:
    for token in list(token_blacklist.keys()):
        item = token_blacklist.get(token, None)
        if item is None:
            continue
        if token_blacklist[token] < datetime.now(timezone.utc):
            print(f"{datetime.now(timezone.utc)}|INFO|main.py|Removing token {token}")
            del token_blacklist[token]


def is_token_blacklisted(token: str) -> bool:
    return token in list(token_blacklist.keys())


def __create_access_token__(data: dict, expires_delta: timedelta | None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def __get_current_user__(token: str = Depends(oauth2_scheme)) -> UserEntity:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise EX_ValidationError
    except JWTError:
        raise EX_ValidationError
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not available",
        )
    user: UserEntity | None = await pyappm_server_config.database.find_async(
        "email", email
    )
    if user is None:
        raise EX_ValidationError
    user.token = token
    if user is None:
        raise EX_ValidationError
    user.otp_valid = payload.get("otp_valid")
    return user


def __hash_password__(password: str) -> bytes:
    """
    Hashes a password using bcrypt

    Args:
        password (str): the password to hash

    Returns:
        bytes: the hashed password

    Raises:
        ValueError: if the password is None
        ValueError: if the password is not a string
    """
    if password is None:
        raise ValueError("Password cannot be None")
    if not isinstance(password, str):
        raise ValueError("Password must be a string")
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
    return hashed_password
