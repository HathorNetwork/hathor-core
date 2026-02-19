import asyncio
from typing import Literal

from healthcheck import (
    Healthcheck,
    HealthcheckCallbackResponse,
    HealthcheckInternalComponent,
    HealthcheckResponse,
    HealthcheckStatus,
)
from pydantic import Field
from twisted.internet.defer import Deferred, succeed
from twisted.python.failure import Failure
from twisted.web.http import Request
from twisted.web.server import NOT_DONE_YET

from hathor._openapi.register import register_resource
from hathor.api.openapi import api_endpoint
from hathor.api.schemas import ResponseModel
from hathor.api_util import Resource, get_arg_default, get_args
from hathor.manager import HathorManager
from hathor.util import json_dumpb
from hathor.utils.api import QueryParams


class HealthcheckParams(QueryParams):
    """Query parameters for the /health endpoint."""
    strict_status_code: str | None = Field(
        default=None,
        description="If set to '1', always return 200 status code even if unhealthy"
    )


class HealthcheckComponentResponse(ResponseModel):
    """Response model for a single healthcheck component."""
    componentName: str = Field(description="Name of the component")
    componentType: str = Field(description="Type of the component (e.g., 'internal')")
    status: str = Field(description="Component status ('pass' or 'fail')")
    output: str = Field(description="Human-readable output message")


class HealthcheckSuccessResponse(ResponseModel):
    """Response model for successful healthcheck."""
    status: Literal['pass'] = Field(description="Overall health status")
    description: str = Field(description="Service description including version")
    checks: dict[str, list[HealthcheckComponentResponse]] = Field(
        description="Map of component names to their check results"
    )


class HealthcheckFailResponse(ResponseModel):
    """Response model for failed healthcheck."""
    status: Literal['fail'] = Field(description="Overall health status")
    description: str = Field(description="Service description including version")
    checks: dict[str, list[HealthcheckComponentResponse]] = Field(
        description="Map of component names to their check results"
    )


async def sync_healthcheck(manager: HathorManager) -> HealthcheckCallbackResponse:
    healthy, reason = manager.is_sync_healthy()

    return HealthcheckCallbackResponse(
        status=HealthcheckStatus.PASS if healthy else HealthcheckStatus.FAIL,
        output=reason or 'Healthy',
    )


@register_resource
class HealthcheckResource(Resource):
    isLeaf = True

    def __init__(self, manager: HathorManager):
        self.manager = manager

    def _render_error(self, failure: Failure, request: Request) -> None:
        request.setResponseCode(500)
        request.write(json_dumpb({
            'status': 'fail',
            'reason': f'Internal Error: {failure.getErrorMessage()}',
            'traceback': failure.getTraceback()
        }))
        request.finish()

    def _render_success(self, result: HealthcheckResponse, request: Request) -> None:
        raw_args = get_args(request)
        strict_status_code = get_arg_default(raw_args, 'strict_status_code', '0') == '1'

        if strict_status_code:
            request.setResponseCode(200)
        else:
            status_code = result.get_http_status_code()
            request.setResponseCode(status_code)

        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        request.write(json_dumpb(result.to_json()))
        request.finish()

    @api_endpoint(
        path='/health',
        method='GET',
        operation_id='health',
        summary='Health status of the fullnode',
        description='''Returns 200 if the fullnode should be considered healthy.

Returns 503 otherwise. The response will contain the components that were considered for the healthcheck
and the reason why they were unhealthy.

Optionally, there is a query parameter 'strict_status_code' that can be used to return 200 even if the fullnode
is unhealthy. When its value is 1, the response will always be 200.

We currently perform 2 checks in the sync mechanism for the healthcheck:
1. Whether the fullnode has recent block activity, i.e. if the fullnode has blocks with recent timestamps.
2. Whether the fullnode has at least one synced peer''',
        tags=['healthcheck'],
        visibility='public',
        rate_limit_global=[{'rate': '10r/s', 'burst': 10, 'delay': 5}],
        rate_limit_per_ip=[{'rate': '1r/s', 'burst': 3, 'delay': 2}],
        query_params_model=HealthcheckParams,
        response_model=HealthcheckSuccessResponse,
        error_responses=[HealthcheckFailResponse],
    )
    def render_GET(self, request):
        """ GET request /health/
            Returns the health status of the fullnode

            The 'strict_status_code' argument can be used to return 200 even if the fullnode is unhealthy.
            This can be useful when integrating with tools that could prefer to pass the response code only
            in case the response is 200.

            :rtype: string (json)
        """
        sync_component = HealthcheckInternalComponent(
            name='sync',
        )
        sync_component.add_healthcheck(lambda: sync_healthcheck(self.manager))

        healthcheck = Healthcheck(name='hathor-core', components=[sync_component])

        # The asyncio loop will be running in case the option --x-asyncio-reactor is used
        # XXX: We should remove this if when the asyncio reactor becomes the default and the only option
        if asyncio.get_event_loop().is_running():
            future = asyncio.ensure_future(healthcheck.run())
            deferred = Deferred.fromFuture(future)
        else:
            status = asyncio.get_event_loop().run_until_complete(healthcheck.run())
            deferred = succeed(status)

        deferred.addCallback(self._render_success, request)
        deferred.addErrback(self._render_error, request)

        return NOT_DONE_YET
