# -*- coding: utf-8 -*-
#
# Product:   pyappm server
# Author:    Marco Caspers
# Email:     marco@0xc007.nl
# License:   MIT License
# Date:      2024-07-28
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

# registering a new user:
# POST /api/v1/auth/register
# {
#     "name": "John Doe",
#     "email": "
#     "password": "password"
# }
# Response:
# {
#     "status": "success",
#     "message": "Registered successfully, please login"
# }
# generating a QR code for the OTP:
# PUT /api/v1/auth/otp/generate-qr
# Response:
# {
#     "base32": "base32",
#     "otpauth_url": "otpauth_url"
# }
# verifying the OTP:
# PUT /api/v1/auth/otp/verify
# {
#     "totp_code": "123456"
# }
# Response:
# {
#     "otp_verified": true,
#     "user": {
#         "id": 1,
#         "name": "John Doe",
#         "email": "
#         "hash": "hashed_password",
#         "otp_enabled": true,
#         "otp_verified": true,
#         "otp_base32": "base32",
#         "otp_auth_url": "otpauth_url",
#         "created_at": "2024-07-28T00:00:00Z",
#         "updated_at": "2024-07-28T00:00:00Z",
#         "otp_valid": false
#     }
# }
# validating the OTP:
# POST /api/v1/auth/otp/validate
# {
#     "totp_code": "123456"
# }
# Response:
# {
#     "otp_valid": true,
#     "access
#     "token_type": "bearer"
# }
# disabling the OTP:
# PUT /api/v1/auth/otp/disable
# {
#     "user_id": 1
# }
# Response:
# {
#     "otp_disabled": true,
#     "user": {
#         "id": 1,
#         "name": "John Doe",
#         "email": "
#         "hash": "hashed_password",
#         "otp_enabled": false,
#         "otp_verified": true,
#         "otp_base32": "base32",
#         "otp_auth_url": "otpauth_url",
#         "created_at": "2024-07-28T00:00:00Z",
#         "updated_at": "2024-07-28T00:00:00Z",
#         "otp_valid": false
#     }
# }

# register => generate-qr => verify => validate

import io
import pyotp
import qrcode  # type: ignore
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from schemas import UserRequestSchema
from schemas import OTPResponseModel
from schemas import VerifyResponseModel
from schemas import ValidateResponseModel
from schemas import DisableResponseModel
from schemas import UserEntity

from datetime import timedelta
from fastapi import Depends
import bcrypt  # type: ignore

import pyappm_server_config

from pyappm_auth_tools import ACCESS_TOKEN_EXPIRE_MINUTES
from pyappm_auth_tools import ACCESS_TOKEN_EXPIRE_MINUTES_SHORT
from pyappm_auth_tools import __create_access_token__
from pyappm_auth_tools import __get_current_user__
from pyappm_auth_tools import blacklist_token
from pyappm_auth_tools import __hash_password__
from pyappm_auth_tools import is_token_blacklisted

router = APIRouter()


async def __create_qr_code__(otp_base32: str, user: UserEntity) -> bytes:
    """
    Creates a QR code for the OTP

    Args:
        otp_base32 (str): The base32 string for the OTP
        user (UserEntity): The user entity to create the QR code for

    Returns:
        None
    """
    totp = pyotp.TOTP(otp_base32)
    uri = totp.provisioning_uri(name=user.email, issuer_name="pyappm.nl")
    img = qrcode.make(uri)
    img_byte_array = io.BytesIO()
    img.save(img_byte_array)
    img_byte_array.seek(0)
    return img_byte_array.getvalue()


def __verify_password__(plain_password: str, hashed_password: bytes) -> bool:
    """
    Verifies if the plain password matches the hashed password

    Args:
        plain_password (str): The plain text password
        hashed_password (bytes): The hashed password to validate against

    Returns:
        bool: True if the passwords match, False otherwise

    Raises:
        ValueError: if the password is None
        ValueError: if the password is not a string
        ValueError: if the hashed password is None
        ValueError: if the hashed password is not a bytes object
    """
    if plain_password is None:
        raise ValueError("Password cannot be None")
    if not isinstance(plain_password, str):
        raise ValueError("Password must be a string")
    if hashed_password is None:
        raise ValueError("Hashed password cannot be None")
    if not isinstance(hashed_password, bytes):
        raise ValueError("Hashed password must be a bytes object")
    password_byte_enc = plain_password.encode("utf-8")
    return bcrypt.checkpw(password=password_byte_enc, hashed_password=hashed_password)


async def __verify_password_async__(
    plain_password: str, hashed_password: bytes
) -> bool:
    return __verify_password__(plain_password, hashed_password)


@router.put("/generate-qr", response_model=OTPResponseModel)
async def generate_otp(
    payload: UserEntity = Depends(__get_current_user__),
) -> StreamingResponse:
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found",
        )
    if payload.token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid",
        )
    if is_token_blacklisted(str(payload.token)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is blacklisted",
        )
    otp_base32 = pyotp.random_base32()
    otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
        payload.email, issuer_name="pyappm.nl"
    )
    payload.otp_base32 = otp_base32
    payload.otp_auth_url = otp_auth_url
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not found",
        )
    pyappm_server_config.database.update_user(payload)
    qr_code = await __create_qr_code__(otp_base32, payload)

    return StreamingResponse(io.BytesIO(qr_code), media_type="image/png")


@router.put("/verify", response_model=VerifyResponseModel)
async def verify_otp(
    totp_code: str, user: UserEntity = Depends(__get_current_user__)
) -> VerifyResponseModel:
    message = "Token is invalid or user doesn't exist"
    verify_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=message,
    )
    if user is None:
        raise verify_exception
    if user.token is None:
        raise verify_exception
    if is_token_blacklisted(str(user.token)):
        raise verify_exception
    totp = pyotp.TOTP(user.otp_base32)  # type: ignore
    if not totp.verify(totp_code):  # type: ignore
        raise verify_exception
    user.otp_enabled = True
    user.otp_verified = True
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not found",
        )
    verified_user: UserEntity | None = (
        await pyappm_server_config.database.update_user_async(user)
    )
    if verified_user is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user",
        )
    return VerifyResponseModel(otp_verified=True, user=verified_user)


@router.post("/validate", response_model=ValidateResponseModel)
def validate_otp(
    totp_code: str, user: UserEntity = Depends(__get_current_user__)
) -> ValidateResponseModel:
    validate_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Token is invalid or user doesn't exist",
    )
    if user is None:
        raise validate_exception
    if user.token is None:
        raise validate_exception
    if is_token_blacklisted(str(user.token)):
        raise validate_exception
    if not user.otp_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP must be verified first",
        )
    totp = pyotp.TOTP(user.otp_base32)  # type: ignore
    if not totp.verify(totp_code):  # type: ignore
        validate_exception
    token = __create_access_token__(
        data={"sub": user.email, "otp_valid": True},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    blacklist_token(user.token, ACCESS_TOKEN_EXPIRE_MINUTES_SHORT)
    return ValidateResponseModel(
        otp_valid=True, access_token=token, token_type="bearer"
    )


@router.put("/disable", response_model=DisableResponseModel)
def disable_otp(payload: UserRequestSchema) -> DisableResponseModel:
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid payload",
        )
    if payload.user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user_id",
        )
    if is_token_blacklisted(str(payload.token)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is blacklisted",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database not found",
        )
    user = pyappm_server_config.database.find_user_by_id(int(payload.user_id))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid id: {payload.user_id}",
        )
    user.otp_enabled = False
    pyappm_server_config.database.update_user(user)
    return DisableResponseModel(otp_disabled=True, user=user)
