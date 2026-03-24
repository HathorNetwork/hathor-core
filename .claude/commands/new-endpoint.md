---
description: Scaffold a new REST API resource + test
---

Create a new REST API endpoint for hathor-core. The resource name/path is: $ARGUMENTS

Steps:
1. Create the resource file in the appropriate `hathor/**/resources/` directory
2. Use this template:

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
        # The decorator handles:
        #   - Query param validation (passed as params= kwarg)
        #   - Response serialization to JSON
        #   - Content-Type and CORS headers
        #   - HathorError exception catching → ErrorResponse
        # Just return a ResponseModel instance.
        return MySuccessResponse(...)
```

Key points about the `@api_endpoint` decorator:
- **No manual `set_cors()` or `json_dumpb()`** — the decorator handles both automatically
- **No `.openapi` dict on the class** — OpenAPI spec is generated from the decorator params and models
- **Query params**: define a `QueryParams` subclass, pass as `query_params_model=`, receive as `*, params:` kwarg
- **Request body**: define a model, pass as `request_model=`, receive as `*, body:` kwarg (for POST/PUT)
- **Response**: return a `ResponseModel` subclass; use `Union[A, B]` for multiple possible responses
- **Async**: return a `Deferred` that resolves to a `ResponseModel`; decorator handles `NOT_DONE_YET`

3. Create matching test file in `hathor_tests/` mirroring the source path
   - Use `_ResourceTest` base class
   - Set up `StubSite` wrapping the resource
   - Test happy path and error cases
4. Show the user both files and explain how to wire the resource into the URL router
