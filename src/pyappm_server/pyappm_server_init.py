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

from pathlib import Path

import getpass

from default import reset_database_to_default  # type: ignore
from default import register_default_user

from config import DEFAULT_APP_NAME  # type: ignore
from config import DEFAULT_DB_FILE_PATH
from config import DEFAULT_CLIENT_ORIGIN

from pyappm_database import Database  # type: ignore

from schemas import Settings  # type: ignore

import secrets


def install() -> None:
    print("Installing pyappm server")
    print("Creating environment variables")
    with open(".env", "w") as env_file:
        env_file.write(f'APP_NAME="{DEFAULT_APP_NAME}"\n')
        env_file.write(f'DB_FILE_PATH="{DEFAULT_DB_FILE_PATH}"\n')
        env_file.write(f'CLIENT_ORIGIN="{DEFAULT_CLIENT_ORIGIN}"\n')
        env_file.write(f'SECRET_KEY="{secrets.token_hex(32)}"\n')
        env_file.write(f'ALGORITHM="HS256"\n')
    print("Environment variables have been created.")
    print("Creating the database.")
    settings = Settings(
        app_name=DEFAULT_APP_NAME,
        db_file_path=DEFAULT_DB_FILE_PATH,
        client_origin=DEFAULT_CLIENT_ORIGIN,
    )
    path = Path(settings.db_file_path).parent
    if not path.exists():
        path.mkdir(parents=True)
    database = Database(settings)
    reset_database_to_default(database)
    print("The database has been created.")
    print("Creating a user.")
    user_name: str = input("Enter the user name: ")
    user_email: str = input("Enter the email address: ")
    user_password: str = getpass.getpass("Enter a password: ")
    user_password_repeat: str = getpass.getpass("Repeat the password: ")
    if user_password != user_password_repeat:
        print("The passwords do not match. Exiting.")
        return
    register_default_user(
        db=database,
        user=user_name,
        email=user_email,
        password=user_password,
    )
    print("The user has been created.")

    print("Installation complete.")


if __name__ == "__main__":
    install()
