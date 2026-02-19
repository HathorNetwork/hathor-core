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

from dataclasses import dataclass
from typing import Any, Callable, Literal, TypeVar

from pydantic import BaseModel

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
    response_model: type[BaseModel] | None
    error_responses: list[type[BaseModel]]
    deprecated: bool
    path_params_regex: dict[str, str]


# Global registry of endpoint metadata
_endpoint_registry: list[EndpointMetadata] = []


def get_endpoint_registry() -> list[EndpointMetadata]:
    """Get all registered endpoint metadata."""
    return _endpoint_registry


def clear_endpoint_registry() -> None:
    """Clear the endpoint registry. Useful for testing."""
    _endpoint_registry.clear()


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
    response_model: type[BaseModel] | None = None,
    error_responses: list[type[BaseModel]] | None = None,
    deprecated: bool = False,
    path_params_regex: dict[str, str] | None = None,
) -> Callable[[F], F]:
    """Decorator to register an endpoint with OpenAPI metadata.

    This decorator:
    1. Registers the endpoint metadata for OpenAPI spec generation
    2. Can be used to auto-validate requests (future enhancement)

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
        response_model: Pydantic model for successful response
        error_responses: List of Pydantic models for error responses
        deprecated: Whether this endpoint is deprecated
        path_params_regex: Regex patterns for path parameters

    Example:
        @api_endpoint(
            path='/version',
            method='GET',
            operation_id='version',
            summary='Get Hathor version info',
            response_model=VersionResponse,
            tags=['general'],
        )
        def render_GET(self, request):
            ...
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
            error_responses=error_responses or [],
            deprecated=deprecated,
            path_params_regex=path_params_regex or {},
        )

        # Store metadata on the function for later retrieval
        func._openapi_metadata = metadata  # type: ignore[attr-defined]

        # Register in global registry
        _endpoint_registry.append(metadata)

        return func

    return decorator
