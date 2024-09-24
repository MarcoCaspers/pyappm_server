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

# Description:
#
# This is the api router for the base_url/ endpoints.

from fastapi import APIRouter  # type: ignore

from schemas import MessageResponseModel

from __about__ import __version__  # type: ignore

router = APIRouter()


@router.get("/", response_model=MessageResponseModel)
def root() -> MessageResponseModel:
    return MessageResponseModel(message="Python application manager server")


@router.get("/health", response_model=MessageResponseModel)
def health() -> MessageResponseModel:
    return MessageResponseModel(message="Python application manager server is healthy")


@router.get("/version", response_model=MessageResponseModel)
def version() -> MessageResponseModel:
    return MessageResponseModel(
        message=f"Python application manager server version {__version__}"
    )
