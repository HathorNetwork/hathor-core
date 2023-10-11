import hathor
from hathor.api_util import Resource
from hathor.cli.openapi_files.register import register_resource
from hathor.healthcheck.models import ComponentHealthCheck, ComponentType, HealthCheckStatus, ServiceHealthCheck
from hathor.manager import HathorManager
from hathor.util import json_dumpb


def build_sync_health_status(manager: HathorManager) -> ComponentHealthCheck:
    """Builds the sync health status object."""
    healthy, reason = manager.is_sync_healthy()

    return ComponentHealthCheck(
        component_name="sync",
        component_type=ComponentType.INTERNAL,
        status=HealthCheckStatus.PASS if healthy else HealthCheckStatus.FAIL,
        output=reason or "Healthy",
    )


@register_resource
class HealthcheckResource(Resource):
    isLeaf = True

    def __init__(self, manager: HathorManager):
        self.manager = manager

    def render_GET(self, request):
        """ GET request /health/
            Returns the health status of the fullnode

            :rtype: string (json)
        """
        components_health_checks = [
            build_sync_health_status(self.manager)
        ]

        health_check = ServiceHealthCheck(
            description=f"Hathor-core {hathor.__version__}",
            checks={c.component_name: [c] for c in components_health_checks},
        )

        request.setResponseCode(health_check.get_http_status_code())
        return json_dumpb(health_check.to_json())


# TODO: Fix below
HealthcheckResource.openapi = {
    '/health': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '10r/s',
                    'burst': 10,
                    'delay': 5
                }
            ],
            'per-ip': [
                {
                    'rate': '1r/s',
                    'burst': 3,
                    'delay': 2
                }
            ]
        },
        'get': {
            'tags': ['healthcheck'],
            'operationId': 'get',
            'summary': 'Health status of the fullnode',
            'description': '''
Returns 200 if the fullnode should be considered healthy.

Returns 503 otherwise. The response will contain the components that were considered for the healthcheck
and the reason why they were unhealthy.

We currently perform 2 checks in the sync mechanism for the healthcheck:
1. Whether the fullnode has recent block activity, i.e. if the fullnode has blocks with recent timestamps.
2. Whether the fullnode has at least one synced peer
            ''',
            'responses': {
                '200': {
                    'description': 'Healthy',
                    'content': {
                        'application/json': {
                            'examples': {
                                'healthy': {
                                    'summary': 'Healthy node',
                                    'value': {
                                        'status': 'pass',
                                        'description': 'Hathor-core v0.56.0',
                                        'checks': {
                                            'sync': [
                                                {
                                                    'componentName': 'sync',
                                                    'componentType': 'internal',
                                                    'status': 'pass',
                                                    'output': 'Healthy'
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                '503': {
                    'description': 'Unhealthy',
                    'content': {
                        'application/json': {
                            'examples': {
                                'no_recent_activity': {
                                    'summary': 'Node with no recent activity',
                                    'value': {
                                        'status': 'fail',
                                        'description': 'Hathor-core v0.56.0',
                                        'checks': {
                                            'sync': [
                                                {
                                                    'componentName': 'sync',
                                                    'componentType': 'internal',
                                                    'status': 'fail',
                                                    'output': 'Node doesn\'t have recent blocks'
                                                }
                                            ]
                                        }
                                    }
                                },
                                'no_synced_peer': {
                                    'summary': 'Node with no synced peer',
                                    'value': {
                                        'status': 'fail',
                                        'description': 'Hathor-core v0.56.0',
                                        'checks': {
                                            'sync': [
                                                {
                                                    'componentName': 'sync',
                                                    'componentType': 'internal',
                                                    'status': 'fail',
                                                    'output': 'Node doesn\'t have a synced peer'
                                                }
                                            ]
                                        }
                                    }
                                },
                                'peer_best_block_far_ahead': {
                                    'summary': 'Peer with best block too far ahead',
                                    'value': {
                                        'status': 'fail',
                                        'description': 'Hathor-core v0.56.0',
                                        'checks': {
                                            'sync': [
                                                {
                                                    'componentName': 'sync',
                                                    'componentType': 'internal',
                                                    'status': 'fail',
                                                    'output': 'Node\'s peer with highest height is too far ahead.'
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}
