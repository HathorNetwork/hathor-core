from hathor._openapi.register import register_resource
from hathor.api_util import Resource
from hathor.manager import HathorManager
from hathor.util import json_dumpb


@register_resource
class HealthcheckReadinessResource(Resource):
    isLeaf = True

    def __init__(self, manager: HathorManager):
        self.manager = manager

    def render_GET(self, request):
        """ GET request /p2p/readiness/
            Checks if the fullnode is considered ready from the perpective of the sync mechanism

            :rtype: string (json)
        """
        healthy, reason = self.manager.is_sync_healthy()

        if not healthy:
            request.setResponseCode(503)
            return json_dumpb({'success': False, 'reason': reason})

        return json_dumpb({'success': True})


HealthcheckReadinessResource.openapi = {
    '/p2p/readiness': {
        'x-visibility': 'public',
        'x-rate-limit': {
            'global': [
                {
                    'rate': '200r/s',
                    'burst': 200,
                    'delay': 100
                }
            ],
            'per-ip': [
                {
                    'rate': '3r/s',
                    'burst': 10,
                    'delay': 3
                }
            ]
        },
        'get': {
            'tags': ['p2p'],
            'operationId': 'readiness',
            'summary': 'Readiness status of the fullnode',
            'description': '''
Returns 200 if the fullnode should be considered ready from the perspective of the sync mechanism.

Returns 503 otherwise. The response will contain the reason why it is not ready in this case.

We currently check 2 things for the readiness:
1. Whether the fullnode has recent block activity, i.e. if the fullnode has blocks with recent timestamps.
2. Whether the fullnode has at least one synced peer

It's possible to customize the behavior of this endpoint by tweaking what should be considered recent activity.
See the setting P2P_RECENT_ACTIVITY_THRESHOLD_MULTIPLIER and the comment above it in hathor/conf/settings.py
for more info.
            ''',
            'responses': {
                '200': {
                    'description': 'Ready',
                    'content': {
                        'application/json': {
                            'examples': {
                                'ready': {
                                    'summary': 'Ready',
                                    'value': {
                                        'success': True
                                    }
                                }
                            }
                        }
                    }
                },
                '503': {
                    'description': 'Not Ready',
                    'content': {
                        'application/json': {
                            'examples': {
                                'no_recent_activity': {
                                    'summary': 'Node with no recent activity',
                                    'value': {
                                        'success': False,
                                        'reason': "Node doesn't have recent blocks"
                                    }
                                },
                                'no_synced_peer': {
                                    'summary': 'Node with no synced peer',
                                    'value': {
                                        'success': False,
                                        'reason': "Node doesn't have a synced peer"
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
