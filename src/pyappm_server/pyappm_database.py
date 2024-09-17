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


import sqlite3 as sql
from typing import Any
from datetime import datetime

from schemas import UserToRegisterSchema  # type: ignore
from schemas import UserEntity
from schemas import SaferUserEntity
from schemas import ApplicationAuthorSchema
from schemas import ApplicationSchema
from schemas import Settings

from fastapi import HTTPException


class Database:
    def __init__(self, settings: Settings) -> None:
        self.db_name: str = ""
        self.opened: bool = False
        self.open(settings.db_file_path)

    def execute_query(self, query: str) -> None:
        self.cursor.execute(query)
        self.conn.commit()

    def execute(self, query: str, values: tuple) -> None:
        try:
            self.cursor.execute(query, values)
            self.conn.commit()
        except sql.Error as e:
            print(f"Error: {e}")

    def fetch_query(self, query: str) -> list[Any]:
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def fetch(self, query: str, values: tuple) -> list[Any]:
        self.cursor.execute(query, values)
        return self.cursor.fetchall()

    def open(self, db_name: str) -> None:
        if self.opened:
            raise Exception("Database already open")
        self.db_name = db_name
        self.conn = sql.connect(db_name)
        self.cursor = self.conn.cursor()
        self.opened = True

    def close(self) -> None:
        if not self.opened:
            return  # nothing to do, we weren't open
        if self.conn is None:
            return  # something bad happened, and we're dead
        if self.conn.in_transaction:
            self.conn.rollback()  # rollback any open transactions
        self.conn.close()
        self.opened = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
        if exc_type:
            print(f"Exception: {exc_type} {exc_val} {exc_tb}")

    def __table_exists__(self, table_name: str) -> bool:
        test = self.fetch(
            f"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        return test is not None and len(test) > 0

    def create_users_table(self) -> None:
        """Create the users table"""
        self.execute_query(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                hash TEXT NOT NULL,
                otp_enabled INTEGER NOT NULL CHECK (otp_enabled IN (0, 1)),
                otp_verified INTEGER NOT NULL CHECK (otp_verified IN (0, 1)),
                otp_base32 TEXT,
                otp_auth_url TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

    def create_app_table(self) -> None:
        """Create the application table"""
        self.execute_query(
            """
            CREATE TABLE IF NOT EXISTS app (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                version TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
            """
        )

    def create_authors_table(self) -> None:
        """Create the authors table"""
        self.execute_query(
            """
            CREATE TABLE IF NOT EXISTS authors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (app_id) REFERENCES app(id)
            )
            """
        )

    def __drop_table__(self, table_name: str) -> None:
        """Drop the table"""
        self.execute_query(f"DROP TABLE IF EXISTS {table_name}")

    def drop_users_table(self) -> None:
        """Drop the users table"""
        self.__drop_table__("users")

    def drop_app_table(self) -> None:
        """Drop the application table"""
        self.__drop_table__("app")

    def drop_authors_table(self) -> None:
        """Drop the authors table"""
        self.__drop_table__("authors")

    def create_user(self, user: UserToRegisterSchema) -> None:
        cmd = f"INSERT INTO users (name, email, hash, otp_enabled, otp_verified, otp_base32 , otp_auth_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        self.execute(
            cmd,
            (
                user.name,
                user.email,
                user.password,
                user.otp_enabled,
                user.otp_verified,
                user.otp_base32,
                user.otp_auth_url,
                user.created_at,
                user.updated_at,
            ),
        )

    def __user_from_row__(self, row: Any) -> UserEntity:
        # print(row)
        return UserEntity(
            id=int(row[0]),
            name=row[1],
            email=row[2],
            hash=str(row[3]).encode("utf-8"),
            otp_enabled=bool(row[4]),
            otp_verified=bool(row[5]),
            otp_base32=row[6],
            otp_auth_url=row[7],
            created_at=datetime.fromisoformat(row[8]),
            updated_at=datetime.fromisoformat(row[9]),
        )

    def find_user_by_name(self, name: str) -> UserEntity | None:
        return self.find("name", name)

    def find_user_by_email(self, email: str) -> UserEntity | None:
        return self.find("email", email)

    def find(self, field: str, value: Any) -> UserEntity | None:
        row = self.fetch(f"SELECT * FROM users WHERE {field}=?", (value,))
        if row is None:
            return None
        if len(row) == 0:
            return None
        if isinstance(row, list):
            row = row[0]
        return self.__user_from_row__(row)

    async def find_async(self, field: str, value: Any) -> UserEntity | None:
        return self.find(field, value)

    def find_user_by_id(self, user_id: int) -> UserEntity | None:
        return self.find("id", user_id)

    def is_valid_user_id(self, user_id: int) -> bool:
        return self.find("id", user_id) is not None

    async def read_users_async(self) -> list[SaferUserEntity]:
        rows = self.fetch_query("SELECT * FROM users")
        if rows is None:
            return []
        return [
            SaferUserEntity(**self.__user_from_row__(row).model_dump()) for row in rows
        ]

    def read_users(self) -> list[SaferUserEntity]:
        rows = self.fetch_query("SELECT * FROM users")
        if rows is None:
            return []
        return [
            SaferUserEntity(**self.__user_from_row__(row).model_dump()) for row in rows
        ]

    async def read_user_async(self, user_id: int) -> SaferUserEntity | None:
        user = self.find_user_by_id(user_id)
        if user is None:
            return None
        return SaferUserEntity(**user.model_dump())

    def update_user(self, user: UserEntity) -> UserEntity:
        cmd = f"UPDATE users SET name=?, email=?, otp_enabled=?, otp_verified=?, otp_base32=?, otp_auth_url=?, updated_at=? WHERE id=?"
        self.execute(
            cmd,
            (
                user.name,
                user.email,
                user.otp_enabled,
                user.otp_verified,
                user.otp_base32,
                user.otp_auth_url,
                user.updated_at,
                user.id,
            ),
        )
        return self.find_async("id", user.id)

    async def update_user_async(self, user: UserEntity) -> None:
        self.update_user(user)

    def delete_user(self, user_id: int) -> None:
        self.execute(f"DELETE FROM users WHERE id=?", (user_id,))

    def create_app(self, app: ApplicationSchema) -> None:
        cmd = f"INSERT INTO app (owner_id, name, type, version, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        self.execute(
            cmd,
            (
                app.owner_id,
                app.name,
                app.type,
                app.version,
                app.description,
                app.created_at,
                app.updated_at,
            ),
        )

    def __apps_from_rows__(self, rows: list) -> list[ApplicationSchema]:
        apps_list = []
        for row in rows:
            id = int(row[0])
            owner_id = int(row[1])
            name = row[2]
            type = row[3]
            version = row[4]
            description = row[5]
            created_at = datetime.fromisoformat(row[6])
            updated_at = datetime.fromisoformat(row[7])
            app = ApplicationSchema(
                id=id,
                owner_id=owner_id,
                name=name,
                type=type,
                version=version,
                description=description,
                created_at=created_at,
                updated_at=updated_at,
            )
            apps_list.append(app)
        return apps_list

    def find_app_by_name(self, name: str) -> list[ApplicationSchema] | None:
        return self.find_app("name", name)

    async def find_app_by_name_async(self, name: str) -> list[ApplicationSchema] | None:
        return self.find_app_by_name(name)

    def find_app_by_id(self, app_id: int) -> ApplicationSchema | None:
        app = self.find_app("id", app_id)
        if app is None:
            return None
        return app[0]

    async def find_app_by_id_async(self, app_id: int) -> ApplicationSchema | None:
        return self.find_app_by_id(app_id)

    def find_app(self, field: str, value: Any) -> list[ApplicationSchema] | None:
        rows = self.fetch(f"SELECT * FROM app WHERE {field}=?", (value,))
        if rows is None:
            return None
        if len(rows) == 0:
            return None
        return self.__apps_from_rows__(rows)

    def read_apps_by_owner_id(self, owner_id: int) -> list[ApplicationSchema]:
        rows = self.find_app("owner_id", owner_id)
        if rows is None:
            return []
        return rows

    async def read_apps_by_owner_id_async(
        self, owner_id: int
    ) -> list[ApplicationSchema]:
        return self.read_apps_by_owner_id(owner_id)

    def read_apps(self) -> list[ApplicationSchema]:
        rows = self.fetch_query("SELECT * FROM app")
        if rows is None:
            return []
        return self.__apps_from_rows__(rows)

    async def read_apps_async(self) -> list[ApplicationSchema]:
        return self.read_apps()

    def update_app(self, app_id: int, app: ApplicationSchema) -> ApplicationSchema:
        cmd = f"UPDATE app SET owner_id=?, name=?, type=?, version=?, description=?, updated_at=? WHERE id=?"
        self.execute(
            cmd,
            (
                app.owner_id,
                app.name,
                app.type,
                app.version,
                app.description,
                app.updated_at,
                app_id,
            ),
        )
        return self.find_app_by_id(app_id)

    def delete_app(self, app_id: int) -> None:
        self.execute(f"DELETE FROM app WHERE id=?", (app_id,))

    async def delete_app_async(self, app_id: int) -> None:
        self.delete_app(app_id)

    def create_author(self, author: ApplicationAuthorSchema) -> None:
        cmd = f"INSERT INTO authors (app_id, name, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
        self.execute(
            cmd,
            (
                author.app_id,
                author.name,
                author.email,
                author.created_at,
                author.updated_at,
            ),
        )

    def __authors_from_rows__(self, rows: list) -> list[ApplicationAuthorSchema]:
        return [
            ApplicationAuthorSchema(
                id=int(row[0]),
                app_id=int(row[1]),
                name=row[2],
                email=row[3],
                created_at=datetime.fromisoformat(row[4]),
                updated_at=datetime.fromisoformat(row[5]),
            )
            for row in rows
        ]

    def find_author_by_name(self, name: str) -> list[ApplicationAuthorSchema] | None:
        return self.find_author("name", name)

    def find_author_by_id(self, author_id: int) -> ApplicationAuthorSchema | None:
        author = self.find_author("id", author_id)
        if author is None:
            return None
        return author[0]

    def find_author(
        self, field: str, value: Any
    ) -> list[ApplicationAuthorSchema] | None:
        rows = self.fetch(f"SELECT * FROM authors WHERE {field}=?", (value,))
        if rows is None:
            return None
        if len(rows) == 0:
            return None
        return self.__authors_from_rows__(rows)

    def read_authors(self) -> list[ApplicationAuthorSchema]:
        rows = self.fetch_query("SELECT * FROM authors")
        if rows is None:
            return []
        return self.__authors_from_rows__(rows)

    async def read_authors_async(self) -> list[ApplicationAuthorSchema]:
        return self.read_authors()

    def read_authors_by_app_id(self, app_id: int) -> list[ApplicationAuthorSchema]:
        rows = self.find_author("app_id", app_id)
        if rows is None:
            return []
        return self.__authors_from_rows__(rows)

    async def read_authors_by_app_id_async(
        self, app_id: int
    ) -> list[ApplicationAuthorSchema]:
        return self.read_authors_by_app_id(app_id)

    def update_author(self, author: ApplicationAuthorSchema) -> ApplicationAuthorSchema:
        cmd = f"UPDATE authors SET app_id=?, name=?, email=?, updated_at=? WHERE id=?"
        self.execute(
            cmd,
            (
                author.app_id,
                author.name,
                author.email,
                author.updated_at,
                author.id,
            ),
        )
        return self.find_author_by_id(author.id)

    def delete_author(self, author_id: int) -> None:
        self.execute(f"DELETE FROM authors WHERE id=?", (author_id,))

    def __del__(self) -> None:
        self.close()
