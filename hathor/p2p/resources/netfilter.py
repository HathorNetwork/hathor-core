# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from json import JSONDecodeError
from typing import TYPE_CHECKING, Any

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, get_args, get_missing_params_msg, parse_args, render_options, set_cors
from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.matches import (
    NetfilterMatchAll,
    NetfilterMatchAnd,
    NetfilterMatchIPAddress,
    NetfilterMatchOr,
    NetfilterMatchPeerId,
)
from hathor.p2p.netfilter.matches_remote import NetfilterMatchRemoteURL
from hathor.p2p.netfilter.rule import NetfilterRule
from hathor.p2p.netfilter.targets import NetfilterAccept, NetfilterJump, NetfilterLog, NetfilterReject
from hathor.util import json_dumpb, json_loadb

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


def handle_body_validation(request: 'Request') -> dict[str, Any]:
    """ Auxiliar method to be used by POST and DELETE requests
        to handle the parameters validation
    """
    if request.content is None:
        return {'success': False, 'message': 'No body data'}

    raw_data = request.content.read()
    if raw_data is None:
        return {'success': False, 'message': 'No body data'}

    try:
        data = json_loadb(raw_data)
    except (JSONDecodeError, AttributeError):
        return {'success': False, 'message': 'Invalid format for body data'}

    return {'success': True, 'body': data}


@register_resource
class NetfilterRuleResource(Resource):
    """ Implements a web server API for handling netfilter.

    POST to add a rule, GET to get rules and DELETE to remove a rule.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def render_GET(self, request: 'Request') -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        parsed = parse_args(get_args(request), ['chain'])
        if not parsed['success']:
            return get_missing_params_msg(parsed['missing'])

        args = parsed['args']

        try:
            chain = get_table('filter').get_chain(args['chain'])
        except KeyError:
            return json_dumpb({'success': False, 'message': 'Invalid netfilter chain.'})

        data = {
            'rules': [rule.to_json() for rule in chain.rules]
        }
        return json_dumpb(data)

    def render_POST(self, request: 'Request') -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        data = handle_body_validation(request)

        if not data['success']:
            return json_dumpb(data)

        body = data['body']

        chain = body.get('chain')
        if not chain:
            return json_dumpb({'success': False, 'message': 'Invalid chain data'})

        # Get the filter table chain
        try:
            chain = get_table('filter').get_chain(chain.get('name'))
        except KeyError:
            return json_dumpb({'success': False, 'message': 'Invalid netfilter chain.'})

        # Map of classes string with classes for targets and matches
        # The class name is used in the to_json for the GET API
        # so we expect the same format in the POST in order to allow dump -> reload
        # XXX The dump -> reload won't work for matchAnd, matchOr, and remote URL
        # because their constructor parameters are more complex
        match_classes = [
            NetfilterMatchAll,
            NetfilterMatchAnd,
            NetfilterMatchOr,
            NetfilterMatchIPAddress,
            NetfilterMatchPeerId,
            NetfilterMatchRemoteURL
        ]
        matches = {}
        for match_class in match_classes:
            matches[match_class.__name__] = match_class

        target_classes = [NetfilterAccept, NetfilterReject, NetfilterJump, NetfilterLog]
        targets = {}
        for target_class in target_classes:
            targets[target_class.__name__] = target_class

        # Then we get the match
        match_data = body.get('match')
        match_type = match_data.get('type')
        match_params = match_data.get('match_params', {})

        if match_type not in matches:
            return json_dumpb({'success': False, 'message': 'Invalid netfilter match.'})

        match_class = matches[match_type]

        try:
            match = match_class(**match_params)
        except TypeError:
            return json_dumpb({'success': False, 'message': 'Invalid netfilter match parameters.'})

        # Finally we get the target
        target_data = body.get('target')
        target_type = target_data.get('type')
        target_params = target_data.get('target_params', {})

        if target_type not in targets:
            return json_dumpb({'success': False, 'message': 'Invalid netfilter target.'})

        target_class = targets[target_type]

        try:
            target = target_class(**target_params)
        except TypeError:
            return json_dumpb({'success': False, 'message': 'Invalid netfilter target parameters.'})

        rule = NetfilterRule(match, target)

        chain.add_rule(rule)

        ret = {'success': True, 'rule': rule.to_json()}
        return json_dumpb(ret)

    def render_DELETE(self, request: 'Request') -> bytes:
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'DELETE')

        data = handle_body_validation(request)

        if not data['success']:
            return json_dumpb(data)

        body = data['body']

        # Get the filter table chain
        try:
            chain = get_table('filter').get_chain(body.get('chain'))
        except KeyError:
            return json_dumpb({'success': False, 'message': 'Invalid netfilter chain.'})

        uuid = body.get('rule_uuid')
        if not uuid:
            return json_dumpb({'success': False, 'message': 'Invalid uuid for rule.'})

        removed = chain.delete_rule(uuid)

        if not removed:
            return json_dumpb({'success': False, 'message': 'Rule not found.'})

        ret = {'success': True}
        return json_dumpb(ret)

    def render_OPTIONS(self, request: 'Request') -> int:
        return render_options(request)


NetfilterRuleResource.openapi = {
    '/p2p/netfilter': {
        'x-visibility': 'private',
        'get': {
            'tags': ['p2p', 'netfilter'],
            'operationId': 'p2p_netfilter_rule_get',
            'summary': 'Get netfilter rules by chain',
            'description': 'Returns the list of all netfilter rules from one chain.',
            'parameters': [
                {
                    'name': 'chain',
                    'in': 'query',
                    'description': 'Chain to get the netfilter rules.',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
            ],
            'responses': {
                '200': {
                    'description': 'Success',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Success',
                                    'value': {
                                        'rules': [
                                            {
                                                'uuid': '93095688-8ad5-4b9a-ab6b-c9e7b6d1fab5',
                                                'chain': {
                                                    'name': 'post_peerid',
                                                    'table': {
                                                        'name': 'filter'
                                                    },
                                                    'policy': {
                                                        'type': 'NetfilterAccept',
                                                        'target_params': {}
                                                    }
                                                },
                                                'target': {
                                                    'type': 'NetfilterReject',
                                                    'target_params': {}
                                                },
                                                'match': {
                                                    'type': 'NetfilterMatchPeerId',
                                                    'match_params': {
                                                        'peer_id': ('f7397705bc07aabf6fc3f68de6605d93b'
                                                                    '560bc832d9ebbdfb0d3bd41e1f9480b')
                                                    }
                                                },
                                            },
                                            {
                                                'uuid': '93095688-8ad5-4b9a-ab6b-c9e7b6d1fab5',
                                                'chain': {
                                                    'name': 'post_peerid',
                                                    'table': {
                                                        'name': 'filter'
                                                    },
                                                    'policy': {
                                                        'type': 'NetfilterAccept',
                                                        'target_params': {}
                                                    }
                                                },
                                                'target': {
                                                    'type': 'NetfilterLog',
                                                    'target_params': {
                                                        'msg': 'Wat'
                                                    }
                                                },
                                                'match': {
                                                    'type': 'NetfilterMatchPeerId',
                                                    'match_params': {
                                                        'peer_id': ('f7397705bc07aabf6fc3f68de6605d93b'
                                                                    '560bc832d9ebbdfb0d3bd41e1f9480b')
                                                    }
                                                },
                                            }
                                        ]
                                    }
                                },
                                'error': {
                                    'summary': 'Chain not found',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid netfilter chain.'
                                    }
                                },
                            }
                        }
                    }
                }
            }
        },
        'post': {
            'tags': ['p2p', 'netfilter'],
            'operationId': 'p2p_netfilter_rule_add',
            'summary': 'Add p2p netfilter rule',
            'description': 'Add netfilter rules.',
            'requestBody': {
                'description': 'Netfilter rule data to add.',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'description': 'Data of rule to add in the netfilter chain.',
                            'properties': {
                                'chain': 'string',
                                'match': 'string',
                                'match_params': 'object',
                                'target': 'string',
                                'target_params': 'object',
                            }
                        },
                        'examples': {
                            'peer_id_reject': {
                                'summary': 'Add rule to reject a peer id',
                                'value': {
                                    'chain': {
                                        'name': 'post_peerid',
                                    },
                                    'target': {
                                        'type': 'NetfilterReject',
                                        'target_params': {}
                                    },
                                    'match': {
                                        'type': 'NetfilterMatchPeerId',
                                        'match_params': {
                                            'peer_id': ('f7397705bc07aabf6fc3f68de6605d93b'
                                                        '560bc832d9ebbdfb0d3bd41e1f9480b')
                                        }
                                    },
                                }
                            },
                        }
                    }
                }
            },
            'responses': {
                '200': {
                    'description': 'Add rule.',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Rule added',
                                    'value': {
                                        'success': True,
                                        'uuid': '93095688-8ad5-4b9a-ab6b-c9e7b6d1fab5',
                                        'chain': {
                                            'name': 'post_peerid',
                                            'table': {
                                                'name': 'filter'
                                            },
                                            'policy': {
                                                'type': 'NetfilterAccept',
                                                'target_params': {}
                                            }
                                        },
                                        'target': {
                                            'type': 'NetfilterReject',
                                            'target_params': {}
                                        },
                                        'match': {
                                            'type': 'NetfilterMatchPeerId',
                                            'match_params': {
                                                'peer_id': ('f7397705bc07aabf6fc3f68de6605d93b'
                                                            '560bc832d9ebbdfb0d3bd41e1f9480b')
                                            }
                                        },
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid chain',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid netfilter chain.',
                                    }
                                },
                                'error2': {
                                    'summary': 'Invalid match',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid netfilter match.',
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        'delete': {
            'tags': ['p2p', 'netfilter'],
            'operationId': 'p2p_netfilter_rule_delete',
            'summary': 'Delete p2p netfilter rule',
            'description': 'Delete netfilter rules.',
            'requestBody': {
                'description': 'Netfilter rule data to delete.',
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'description': 'Data of rule to delete in the netfilter chain.',
                            'properties': {
                                'chain': 'string',
                                'match': 'string',
                                'match_params': 'object',
                                'target': 'string',
                                'target_params': 'object',
                            }
                        },
                        'examples': {
                            'peer_id_reject': {
                                'summary': 'Delete rule to reject a peer id',
                                'value': {
                                    'chain': 'post_peerid',
                                    'rule_uuid': '93095688-8ad5-4b9a-ab6b-c9e7b6d1fab5',
                                }
                            },
                        }
                    }
                }
            },
            'responses': {
                '200': {
                    'description': 'Delete rules.',
                    'content': {
                        'application/json': {
                            'examples': {
                                'success': {
                                    'summary': 'Rule deleted',
                                    'value': {
                                        'success': True
                                    }
                                },
                                'error': {
                                    'summary': 'Invalid chain',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid netfilter chain.',
                                    }
                                },
                                'error2': {
                                    'summary': 'Invalid match',
                                    'value': {
                                        'success': False,
                                        'message': 'Invalid netfilter match.',
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
