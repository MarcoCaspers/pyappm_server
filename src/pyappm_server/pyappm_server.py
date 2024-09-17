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


# Description:
#
# This is the main entry point for the pyappm_server application
#
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # type: ignore

from pyappm_database import Database  # type: ignore

from schemas import Settings  # type: ignore

import config  # type: ignore
from config import API_VERSION_PATH  # type: ignore
from config import DEFAULT_BLACKLIST_CLEANUP_INTERVAL  # type: ignore

from pyappm_otp_auth_router import router as otp_auth_router  # type: ignore
from pyappm_std_auth_router import router as std_auth_router  # type: ignore
from pyappm_admin_router import router as admin_router  # type: ignore
from pyappm_apps_router import router as apps_router  # type: ignore
from pyappm_root_router import router as root_router  # type: ignore

from pyappm_auth_tools import cleanup_blacklist  # type: ignore

from argparse import ArgumentParser, Namespace
from pathlib import Path

from contextlib import asynccontextmanager
import asyncio
from datetime import datetime, timezone


async def blacklist_cleanup_task(interval: int) -> None:
    mutex = False
    while True:
        await asyncio.sleep(interval)
        if mutex:
            print(
                f"{datetime.now(timezone.utc)}|INFO|main.py|Task still running, skipping"
            )
            continue
        mutex = True
        print(
            f"{datetime.now(timezone.utc)}|INFO|main.py|Running blacklist cleanup task"
        )
        cleanup_blacklist()
        mutex = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(blacklist_cleanup_task(DEFAULT_BLACKLIST_CLEANUP_INTERVAL))
    yield


app: FastAPI = FastAPI(
    title="Python application manager api server",
    version="1.0.0",
    lifespan=lifespan,
)


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Python application manager server")

    parser.add_argument(
        "-d",
        "--db-file-path",
        type=str,
        default=config.DEFAULT_DB_FILE_PATH,
        help="Path to the database file",
    )
    # parser.add_argument(
    #    "--client-origin",
    #    type=str,
    #    default=config.DEFAULT_CLIENT_ORIGIN,
    #    help="Client origin",
    # )
    return parser.parse_args()


def prefix(path: str) -> str:
    prefx = API_VERSION_PATH
    if path == "root":
        return prefx
    prefx = f"{prefx}/{path}"
    return prefx


def run(app: FastAPI) -> None:
    args = parse_args()
    db_file_path = (
        Path(args.db_file_path, "pyappm.db")
        if Path(args.db_file_path).exists()
        else config.DEFAULT_DB_FILE_PATH
    )
    settings = Settings(
        app_name=config.DEFAULT_APP_NAME,
        db_file_path=db_file_path,
        client_origin=config.DEFAULT_CLIENT_ORIGIN,
    )
    config.database = Database(settings)
    origins = [
        settings.client_origin,
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(root_router, prefix=prefix("root"))
    app.include_router(otp_auth_router, tags=["onetimepassword"], prefix=prefix("otp"))
    app.include_router(std_auth_router, tags=["authentication"])
    app.include_router(admin_router, tags=["administration"], prefix=prefix("admin"))
    app.include_router(apps_router, tags=["applications"], prefix=prefix("apps"))


def main() -> None:
    run(app)
    uvicorn.run(app, host="localhost", port=8000, server_header=False)


if __name__ == "__main__":
    main()
