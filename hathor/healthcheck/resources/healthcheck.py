import asyncio
from typing import ClassVar, Literal, Union

from healthcheck import (
    Healthcheck,
    HealthcheckCallbackResponse,
    HealthcheckInternalComponent,
    HealthcheckResponse,
    HealthcheckStatus,
)
from pydantic import Field
from twisted.internet.defer import Deferred, succeed
from twisted.web.http import Request

from hathor._openapi.register import register_resource
from hathor.api.openapi import api_endpoint
from hathor.api.schemas import OpenAPIExample, ResponseModel
from hathor.api_util import Resource
from hathor.manager import HathorManager
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
    time: str = Field(description="ISO 8601 timestamp of the check")


class HealthcheckSuccessResponse(ResponseModel):
    """Response model for successful healthcheck."""
    response_description: ClassVar[str] = 'Healthy'
    status: Literal['pass'] = Field(description="Overall health status")
    description: str = Field(description="Service description including version")
    checks: dict[str, list[HealthcheckComponentResponse]] = Field(
        description="Map of component names to their check results"
    )


class HealthcheckFailResponse(ResponseModel):
    """Response model for failed healthcheck."""
    http_status_code: ClassVar[int] = 503
    response_description: ClassVar[str] = 'Unhealthy'
    status: Literal['fail'] = Field(description="Overall health status")
    description: str = Field(description="Service description including version")
    checks: dict[str, list[HealthcheckComponentResponse]] = Field(
        description="Map of component names to their check results"
    )


def _sync_component(status: str, output: str) -> HealthcheckComponentResponse:
    return HealthcheckComponentResponse(
        componentName='sync', componentType='internal', status=status, output=output, time='2024-01-01T00:00:00Z',
    )


HealthcheckSuccessResponse.openapi_examples = {
    'healthy': OpenAPIExample(
        summary='Healthy node',
        value=HealthcheckSuccessResponse(
            status='pass',
            description='Hathor-core v0.56.0',
            checks={'sync': [_sync_component('pass', 'Healthy')]},
        ),
    ),
}

HealthcheckFailResponse.openapi_examples = {
    'no_recent_activity': OpenAPIExample(
        summary='Node with no recent activity',
        value=HealthcheckFailResponse(
            status='fail',
            description='Hathor-core v0.56.0',
            checks={'sync': [_sync_component('fail', "Node doesn't have recent blocks")]},
        ),
    ),
    'no_synced_peer': OpenAPIExample(
        summary='Node with no synced peer',
        value=HealthcheckFailResponse(
            status='fail',
            description='Hathor-core v0.56.0',
            checks={'sync': [_sync_component('fail', "Node doesn't have a synced peer")]},
        ),
    ),
    'peer_best_block_far_ahead': OpenAPIExample(
        summary='Peer with best block too far ahead',
        value=HealthcheckFailResponse(
            status='fail',
            description='Hathor-core v0.56.0',
            checks={'sync': [_sync_component('fail', "Node's peer with highest height is too far ahead.")]},
        ),
    ),
}


async def sync_healthcheck(manager: HathorManager) -> HealthcheckCallbackResponse:
    healthy, reason = manager.is_sync_healthy()

    return HealthcheckCallbackResponse(
        status=HealthcheckStatus.PASS if healthy else HealthcheckStatus.FAIL,
        output=reason or 'Healthy',
    )


def _to_response_model(
    result: HealthcheckResponse,
    request: Request,
    strict_status_code: bool,
) -> ResponseModel:
    """Convert a HealthcheckResponse to a Pydantic response model."""
    checks: dict[str, list[HealthcheckComponentResponse]] = {}
    for name, components in result.checks.items():
        checks[name] = [
            HealthcheckComponentResponse(
                componentName=c.component_name,
                componentType=c.component_type,
                status=c.status.value if hasattr(c.status, 'value') else str(c.status),
                output=c.output,
                time=c.time.strftime('%Y-%m-%dT%H:%M:%SZ') if c.time else '',
            )
            for c in components
        ]

    if strict_status_code:
        request._api_status_set = True  # type: ignore[attr-defined]
        request.setResponseCode(200)

    if result.get_http_status_code() == 200:
        return HealthcheckSuccessResponse(
            status='pass',
            description=result.description,
            checks=checks,
        )
    else:
        return HealthcheckFailResponse(
            status='fail',
            description=result.description,
            checks=checks,
        )


@register_resource
class HealthcheckResource(Resource):
    isLeaf = True

    def __init__(self, manager: HathorManager):
        self.manager = manager

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
        response_model=Union[HealthcheckSuccessResponse, HealthcheckFailResponse],
    )
    def render_GET(self, request: Request, *, params: HealthcheckParams) -> Deferred:
        """ GET request /health/
            Returns the health status of the fullnode
        """
        strict_status_code = params.strict_status_code == '1'

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

        deferred.addCallback(_to_response_model, request, strict_status_code)

        return deferred
