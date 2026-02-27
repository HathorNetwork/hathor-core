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

"""Decorators for OpenAPI endpoint documentation and validation."""

import functools
from dataclasses import dataclass
from typing import Any, Callable, ClassVar, Literal, TypeVar

import structlog
from pydantic import BaseModel
from twisted.web.http import Request

from hathor.api.schemas.base import ErrorResponse, ResponseModel

logger = structlog.get_logger()

F = TypeVar('F', bound=Callable[..., Any])

# HTTP methods supported by OpenAPI
HttpMethod = Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH']


@dataclass
class RateLimitConfig:
    """Rate limit configuration for an endpoint."""
    rate: str
    burst: int
    delay: int


@dataclass
class EndpointMetadata:
    """Metadata collected by @api_endpoint decorator."""
    path: str
    method: HttpMethod
    operation_id: str
    summary: str
    description: str
    tags: list[str]
    visibility: str
    rate_limit_global: list[RateLimitConfig]
    rate_limit_per_ip: list[RateLimitConfig]
    query_params_model: type[BaseModel] | None
    request_model: type[BaseModel] | None
    response_model: Any  # Single model or Union of models
    deprecated: bool
    path_params_regex: dict[str, str]
    path_params_descriptions: dict[str, str]


# Global registry of endpoint metadata
_endpoint_registry: list[EndpointMetadata] = []


def get_endpoint_registry() -> list[EndpointMetadata]:
    """Get all registered endpoint metadata."""
    return _endpoint_registry


def clear_endpoint_registry() -> None:
    """Clear the endpoint registry. Useful for testing."""
    _endpoint_registry.clear()


def _serialize_response(result: Any, request: Request) -> bytes:
    """Serialize a response model and set appropriate headers.

    If result is a ResponseModel, serialize it and set the HTTP status code.
    If result is bytes, pass through unchanged.
    """
    if isinstance(result, ResponseModel):
        if not getattr(request, '_api_status_set', False):
            request.setResponseCode(result.http_status_code)
        return result.json_dumpb()
    # Fallback: raw bytes pass through
    return result


class InternalErrorResponse(ResponseModel):
    """500 error response for unhandled Deferred failures."""
    http_status_code: ClassVar[int] = 500
    error: str


def _handle_deferred_error(failure: Any, request: Request) -> None:
    """Errback for Deferred results: log error, write 500 response, finish request."""
    logger.error('unhandled error in deferred endpoint', error=str(failure))
    request.setResponseCode(500)
    response = InternalErrorResponse(error=f'Internal Server Error: {failure.getErrorMessage()}')
    request.write(response.json_dumpb())
    request.finish()


def _handle_deferred_result(result: Any, request: Request) -> None:
    """Callback for Deferred results: serialize and write to request.

    If result is None (e.g., from an errback that already handled the request),
    we skip writing/finishing since the request was already completed.
    """
    if result is None:
        return
    if isinstance(result, ResponseModel):
        if not getattr(request, '_api_status_set', False):
            request.setResponseCode(result.http_status_code)
        request.write(result.json_dumpb())
    else:
        request.write(result)
    request.finish()


def api_endpoint(
    *,
    path: str,
    method: HttpMethod,
    operation_id: str,
    summary: str,
    description: str = '',
    tags: list[str] | None = None,
    visibility: str = 'public',
    rate_limit_global: list[dict[str, Any]] | None = None,
    rate_limit_per_ip: list[dict[str, Any]] | None = None,
    query_params_model: type[BaseModel] | None = None,
    request_model: type[BaseModel] | None = None,
    response_model: Any = None,
    deprecated: bool = False,
    path_params_regex: dict[str, str] | None = None,
    path_params_descriptions: dict[str, str] | None = None,
) -> Callable[[F], F]:
    """Decorator to register an endpoint with OpenAPI metadata and auto-validate/serialize.

    This decorator:
    1. Registers the endpoint metadata for OpenAPI spec generation
    2. Auto-validates query params and request body
    3. Auto-serializes response models and sets HTTP status codes

    The wrapped handler receives:
    - `request` as the first positional arg (Twisted contract)
    - `params=` keyword arg if query_params_model is set
    - `body=` keyword arg if request_model is set

    The handler can return:
    - A ResponseModel instance (auto-serialized, status code set from http_status_code)
    - A Deferred that resolves to a ResponseModel (auto-serialized via callback)
    - Raw bytes (passed through unchanged)
    - NOT_DONE_YET (passed through unchanged)

    Args:
        path: The URL path for this endpoint (e.g., '/version', '/block_at_height')
        method: HTTP method (GET, POST, PUT, DELETE, PATCH)
        operation_id: Unique identifier for this operation
        summary: Short description of the endpoint
        description: Longer description of what the endpoint does
        tags: List of tags for grouping in documentation
        visibility: Visibility level ('public', 'private', 'debug')
        rate_limit_global: Global rate limit configuration
        rate_limit_per_ip: Per-IP rate limit configuration
        query_params_model: Pydantic model for query parameters (GET)
        request_model: Pydantic model for request body (POST/PUT)
        response_model: Pydantic model(s) for response (single or Union)
        deprecated: Whether this endpoint is deprecated
        path_params_regex: Regex patterns for path parameters
        path_params_descriptions: Descriptions for path parameters
    """
    def decorator(func: F) -> F:
        # Parse rate limit configs
        global_limits = [
            RateLimitConfig(rate=rl['rate'], burst=rl['burst'], delay=rl['delay'])
            for rl in (rate_limit_global or [])
        ]
        per_ip_limits = [
            RateLimitConfig(rate=rl['rate'], burst=rl['burst'], delay=rl['delay'])
            for rl in (rate_limit_per_ip or [])
        ]

        metadata = EndpointMetadata(
            path=path,
            method=method,
            operation_id=operation_id,
            summary=summary,
            description=description,
            tags=tags or [],
            visibility=visibility,
            rate_limit_global=global_limits,
            rate_limit_per_ip=per_ip_limits,
            query_params_model=query_params_model,
            request_model=request_model,
            response_model=response_model,
            deprecated=deprecated,
            path_params_regex=path_params_regex or {},
            path_params_descriptions=path_params_descriptions or {},
        )

        @functools.wraps(func)
        def wrapper(self: Any, request: Request, *args: Any, **kwargs: Any) -> Any:
            from twisted.internet.defer import Deferred
            from twisted.web.server import NOT_DONE_YET as _NOT_DONE_YET

            from hathor.api_util import set_cors

            # Set standard headers
            request.setHeader(b'content-type', b'application/json; charset=utf-8')
            set_cors(request, method)

            # Auto-validate query params
            if query_params_model is not None:
                from hathor.utils.api import ErrorResponse as _LegacyErrorResponse

                params = query_params_model.from_request(request)  # type: ignore[attr-defined]
                if isinstance(params, _LegacyErrorResponse):
                    # Validation failed — return 400 error
                    error = ErrorResponse(error=params.error)
                    request.setResponseCode(400)
                    return error.json_dumpb()
                kwargs['params'] = params

            # Auto-validate request body
            if request_model is not None:
                import json as _json

                from pydantic import ValidationError

                try:
                    assert request.content is not None
                    body_bytes = request.content.read()
                    body_data = _json.loads(body_bytes)
                    body = request_model.model_validate(body_data)
                except (ValidationError, _json.JSONDecodeError, UnicodeDecodeError) as e:
                    error = ErrorResponse(error=str(e))
                    request.setResponseCode(400)
                    return error.json_dumpb()
                kwargs['body'] = body

            # Call the actual handler
            result = func(self, request, *args, **kwargs)

            # Auto-serialize response
            if isinstance(result, Deferred):
                result.addCallback(_handle_deferred_result, request)
                result.addErrback(_handle_deferred_error, request)
                return _NOT_DONE_YET
            elif isinstance(result, ResponseModel):
                return _serialize_response(result, request)
            else:
                # Fallback: raw bytes or NOT_DONE_YET pass through
                return result

        # Store metadata on the wrapper for later retrieval
        wrapper._openapi_metadata = metadata  # type: ignore[attr-defined]

        # Register in global registry
        _endpoint_registry.append(metadata)

        return wrapper  # type: ignore[return-value]

    return decorator
