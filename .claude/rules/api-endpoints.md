---
globs: ["hathor/**/resources/**/*.py", "hathor/version_resource.py"]
---

# REST API Endpoint Conventions

## Resource Class Pattern

```python
from hathor.api.openapi import api_endpoint
from hathor.api.openapi.register import register_resource
from hathor.api.schemas.base import ErrorResponse, ResponseModel
from hathor.api_util import Resource
from hathor.utils.api import QueryParams

class MyQueryParams(QueryParams):
    """Query parameters for the endpoint."""
    height: int = Field(description="Height of the block")

class MySuccessResponse(ResponseModel):
    http_status_code: ClassVar[int] = 200
    data: str

@register_resource
class MyResource(Resource):
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager

    @api_endpoint(
        path='/my-endpoint',
        method='GET',
        operation_id='my_endpoint',
        summary='Short description',
        tags=['tag'],
        visibility='public',
        rate_limit_global=[{'rate': '50r/s', 'burst': 100, 'delay': 50}],
        rate_limit_per_ip=[{'rate': '3r/s', 'burst': 10, 'delay': 3}],
        query_params_model=MyQueryParams,
        response_model=Union[MySuccessResponse, ErrorResponse],
    )
    def render_GET(self, request: Request, *, params: MyQueryParams) -> ResponseModel:
        # Just return a ResponseModel — decorator handles JSON, CORS, content-type
        return MySuccessResponse(data='hello')
```

## Key Rules

- Always decorate with `@register_resource` from `hathor.api.openapi.register`
- Set `isLeaf = True` on every resource class
- Use `@api_endpoint(...)` decorator on `render_GET`/`render_POST` — it handles CORS, content-type, and JSON serialization automatically
- **Do NOT** manually call `set_cors()`, `json_dumpb()`, or set content-type headers — the decorator does this
- **Do NOT** define `.openapi` dicts on the class — OpenAPI spec is auto-generated from the decorator params and models
- Define query params as a `QueryParams` subclass → passed as `*, params:` kwarg
- Define request body as a model → pass as `request_model=`, received as `*, body:` kwarg
- Return `ResponseModel` subclasses; use `Union[A, B]` for multiple possible responses
- For async: return a `Deferred` resolving to a `ResponseModel`; decorator handles `NOT_DONE_YET`
- Set `http_status_code: ClassVar[int]` on response models for non-200 status codes

## Scaffolding a New Endpoint

When creating a new resource file in a `hathor/**/resources/` directory, use this template:

```python
#  Copyright <YEAR> Hathor Labs  # Use the current year
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  ...full Apache 2.0 header...

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Union

from hathor.api.openapi import api_endpoint
from hathor.api.openapi.register import register_resource
from hathor.api.schemas.base import ErrorResponse, ResponseModel
from hathor.api_util import Resource
from hathor.utils.api import QueryParams

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


class MyQueryParams(QueryParams):
    """Query parameters for the endpoint."""
    # param_name: str = Field(description="...")


class MySuccessResponse(ResponseModel):
    """Success response."""
    http_status_code: ClassVar[int] = 200
    # field: type


class MyErrorResponse(ResponseModel):
    """Error response."""
    http_status_code: ClassVar[int] = 400
    error: str


@register_resource
class MyResource(Resource):
    isLeaf = True

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager

    @api_endpoint(
        path='/my-endpoint',
        method='GET',
        operation_id='my_endpoint',
        summary='Short description',
        description='Longer description of the endpoint.',
        tags=['tag'],
        visibility='public',
        rate_limit_global=[{'rate': '50r/s', 'burst': 100, 'delay': 50}],
        rate_limit_per_ip=[{'rate': '3r/s', 'burst': 10, 'delay': 3}],
        query_params_model=MyQueryParams,
        response_model=Union[MySuccessResponse, MyErrorResponse],
    )
    def render_GET(self, request: Request, *, params: MyQueryParams) -> ResponseModel:
        return MySuccessResponse(...)
```

After creating the resource, create a matching test file in `hathor_tests/` mirroring the source path using `_ResourceTest` base class with `StubSite`.

## Legacy Pattern (still in some files)

Some older endpoints still use the manual pattern with `set_cors()`, `json_dumpb()`, and `.openapi` dicts. New endpoints should always use `@api_endpoint`. When modifying old endpoints, prefer migrating to the new pattern.
