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
# This is the api router for the base_url/apps endpoints.
# These endpoints are not requiring authentication.
#
# Applications are stored in the database and can be retrieved by id, name or owner id.
# The files for the applications are stored in the uploads directory.
#
# When a file is added, the sha256 hash is calculated and compared with the hash in the request.
# If the hash does not match, the file is not stored.

import hashlib
from pathlib import Path
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status, Depends, File, UploadFile, Body, Form  # type: ignore

from schemas import AppsResponseModel
from schemas import ApplicationSchema
from schemas import UserEntity
from schemas import MessageResponseModel
from schemas import FileResponseModel

import pyappm_server_config

from pyappm_auth_tools import __get_current_user__
from pyappm_auth_tools import is_token_blacklisted

router = APIRouter()


@router.get("/id/{app_id}", response_model=ApplicationSchema)
async def get_app_by_id(app_id: int) -> ApplicationSchema:
    if app_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="App ID not found",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database not found",
        )
    app = await pyappm_server_config.database.find_app_by_id_async(app_id)
    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )
    return app


@router.get("/find/{app_name}", response_model=AppsResponseModel)
async def find_app_by_name(app_name: str) -> AppsResponseModel:
    if app_name is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="App name not found",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database not found",
        )
    app = await pyappm_server_config.database.find_app_by_name_async(app_name)
    if app is None or app == []:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="App not found",
        )
    return app


@router.get("/list", response_model=AppsResponseModel)
async def get_apps_list() -> AppsResponseModel:
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database not found",
        )
    apps = await pyappm_server_config.database.read_apps_async()
    return apps


async def calculate_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


@router.post("/add", response_model=MessageResponseModel)
async def add_app(
    user: UserEntity = Depends(__get_current_user__),
    owner_id: int = Form(...),
    name: str = Form(...),
    type: str = Form(...),
    version: str = Form(...),
    description: str = Form(...),
    sha_256: str = Form(...),
    file: UploadFile = File(...),
) -> MessageResponseModel:
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
    app = ApplicationSchema(
        owner_id=owner_id,
        name=name,
        type=type,
        version=version,
        description=description,
        sha_256=sha_256,
    )
    if file.filename == "":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File not found",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database not found",
        )
    if pyappm_server_config.settings is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Settings not found",
        )
    find_app = await pyappm_server_config.database.find_app_by_name_async(app.name)
    if find_app is not None:
        for found_app in find_app:
            if found_app.name == app.name and found_app.version == app.version:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"App {app.name} ({app.version}) already exists",
                )
    if file.filename is None or file.filename == "":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File not found ({file.filename}) in request",
        )
    if file.content_type != "application/octet-stream":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File is not an application binary ({file.content_type}, {file})",
        )
    if pyappm_server_config.settings.upload_path is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Upload path not found",
        )
    upload_path: Path = Path(pyappm_server_config.settings.upload_path)
    temp_path = upload_path / "temp" / file.filename
    file_path: Path = upload_path / app.name / app.version / file.filename
    with open(temp_path.absolute(), "wb") as f:
        f.write(await file.read())
    sha_256 = await calculate_sha256(temp_path.absolute())
    if sha_256 != app.sha_256:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SHA256 hash does not match",
        )
    if not file_path.parent.exists():
        file_path.parent.mkdir(parents=True)
    temp_path.rename(file_path)
    # await pyappm_server_config.database.create_app_async(app)
    return MessageResponseModel(message=f"App {app.name} ({app.version}) added")


@router.get("/get/{app_name}", response_model=FileResponseModel)
async def get_app_file(
    app_name: str,
    version: str = Form(None),
) -> FileResponseModel:
    if app_name is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="App name not found",
        )
    if pyappm_server_config.database is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database not found",
        )
    if pyappm_server_config.settings is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Settings not found",
        )
    apps = await pyappm_server_config.database.find_app_by_name_async(app_name)
    # if apps is None:
    #    raise HTTPException(
    #        status_code=status.HTTP_404_NOT_FOUND,
    #        detail="App not found",
    #    )
    if pyappm_server_config.settings.upload_path is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Upload path not found",
        )
    upload_path: Path = Path(pyappm_server_config.settings.upload_path)
    # if len(apps) == 0:
    #    raise HTTPException(
    #        status_code=status.HTTP_404_NOT_FOUND,
    #        detail="App not found in database",
    #    )
    # app = apps[0]
    # if version is not None:
    #   app = next((app for app in apps if app.version == version), None)
    #   if app is None:
    #        app = apps[0] # just take the first one if we don't find the version, this is bad!
    dt = datetime.now(timezone.utc)
    app = ApplicationSchema(
        name=app_name,
        version="1.0",
        owner_id=1,
        type="test",
        description="Test",
        created_at=dt,
        updated_at=dt,
    )
    file_path: Path = upload_path / app.name / app.version / f"{app.name}.txt"
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found in file system",
        )
    with open(file_path, "rb") as f:
        file_content = f.read()

    file_response = FileResponseModel(
        file_name=file_path.name,
        file_size=file_path.stat().st_size,
        app_type=app.type,
        app_version=f"{version}, {app.version}",
        file_type="application/octet-stream",
        file_sha256=await calculate_sha256(file_path),
        file=file_content,
        description=app.description,  # type: ignore
        created_at=app.created_at,  # type: ignore
        updated_at=app.updated_at,  # type: ignore
    )
    return file_response
