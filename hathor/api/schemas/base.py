#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Base classes for API request and response models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal

from hathor.utils.pydantic import BaseModel


@dataclass(frozen=True)
class OpenAPIExample:
    """An OpenAPI example with a summary and a validated model instance.

    Using actual model instances ensures examples are validated against the schema
    at definition time.
    """
    summary: str
    value: BaseModel


class RequestModel(BaseModel):
    """Base class for POST/PUT request bodies.

    Inherits from BaseModel with extra='forbid' and frozen=True.
    """
    pass


class ResponseModel(BaseModel):
    """Base class for all API responses.

    Inherits from BaseModel with extra='forbid' and frozen=True.
    The http_status_code ClassVar determines the HTTP status code returned
    by the auto-serialization decorator.

    Subclasses can set:
    - response_description: Custom OpenAPI response description (e.g., "Healthy").
      Defaults to None, in which case the generator uses "Success"/"Error".
    - openapi_examples: Dict of named OpenAPIExample instances for the OpenAPI spec.
      Must be assigned after the class definition since examples reference the class itself.
    """
    http_status_code: ClassVar[int] = 200
    response_description: ClassVar[str | None] = None
    openapi_examples: ClassVar[dict[str, OpenAPIExample] | None] = None


class SuccessResponse(ResponseModel):
    """Standard success response wrapper.

    All successful responses should inherit from this class to ensure
    consistent response format with success=True.
    """
    success: Literal[True] = True


class ErrorResponseModel(ResponseModel):
    """Base class for error responses with no predefined fields.

    Returns HTTP 400 by default. Use this when you need a custom error
    shape that differs from the standard ErrorResponse fields.
    """
    http_status_code: ClassVar[int] = 400


class ErrorResponse(ErrorResponseModel):
    """Standard error response.

    Returns HTTP 400 by default. Subclass and override http_status_code
    for other error status codes.
    """
    success: Literal[False] = False
    error: str
