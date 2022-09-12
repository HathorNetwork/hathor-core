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
from typing import TYPE_CHECKING

from hathor.api_util import Resource, get_args, get_missing_params_msg, parse_args, set_cors, render_options
from hathor.cli.openapi_files.register import register_resource
from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.matches import NetfilterMatchAll, NetfilterMatchAnd, NetfilterMatchOr, NetfilterMatchIPAddress, NetfilterMatchPeerId
from hathor.p2p.netfilter.rule import NetfilterRule
from hathor.p2p.netfilter.targets import NetfilterReject, NetfilterAccept, NetfilterJump, NetfilterLog
from hathor.util import json_dumpb, json_loadb

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


def handle_request(request: 'Request'):
    """ Auxiliar method to be used by POST and DELETE requests
        to handle the parameters validation
    """
    raw_data = request.content.read()
    if raw_data is None:
        return {'success': False, 'message': 'No body data'}

    try:
        data = json_loadb(raw_data)
    except (JSONDecodeError, AttributeError):
        return {'success': False, 'message': 'Invalid format for body data'}

    # Map of available matches and targets with their classes
    matches = {
        'all': NetfilterMatchAll,
        'and': NetfilterMatchAnd,
        'or': NetfilterMatchOr,
        'ip': NetfilterMatchIPAddress,
        'peer_id': NetfilterMatchPeerId,
    }

    targets = {
        'accept': NetfilterAccept,
        'reject': NetfilterReject,
        'jump': NetfilterJump,
        'log': NetfilterLog,
    }

    # First we get the filter table chain
    try:
        chain = get_table('filter').get_chain(data.get('chain'))
    except KeyError:
        return {'success': False, 'message': 'Invalid netfilter chain.'}

    # Then we get the match
    match_value = data.get('match')
    match_params = data.get('match_params', {})

    if match_value not in matches:
        return {'success': False, 'message': 'Invalid netfilter match.'}
    
    match_class = matches.get(match_value)

    try:
        match = match_class(**match_params)
    except TypeError:
        return {'success': False, 'message': 'Invalid netfilter match parameters.'}

    # Finally we get the target
    target_value = data.get('target')
    target_params = data.get('target_params', {})

    if target_value not in targets:
        return {'success': False, 'message': 'Invalid netfilter target.'}

    target_class = targets.get(target_value)

    try:
        target = target_class(**target_params)
    except TypeError:
        return {'success': False, 'message': 'Invalid netfilter target parameters.'}

    rule = NetfilterRule(match, target)

    return {'success': True, 'chain': chain, 'rule': rule}


@register_resource
class NetfilterRuleResource(Resource):
    """ Implements a web server API for handling netfilter.

    POST to add a rule, GET to get rules and DELETE to remove a rule.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager: 'HathorManager'):
        self.manager = manager

    def render_GET(self, request: 'Request'):
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

    def render_POST(self, request: 'Request'):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        data = handle_request(request)

        if not data['success']:
            return json_dumpb(data)

        chain = data['chain']
        rule = data['rule']

        updated_chain = chain.add_rule(rule)

        if updated_chain is None:
            return json_dumpb({'success': False, 'message': 'Duplicated rule.'})

        ret = {'success': True}
        return json_dumpb(ret)

    def render_DELETE(self, request: 'Request'):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'DELETE')

        data = handle_request(request)

        if not data['success']:
            return json_dumpb(data)

        chain = data['chain']
        rule = data['rule']

        removed = chain.delete_rule(rule)

        if not removed:
            return json_dumpb({'success': False, 'message': 'Rule not found.'})

        ret = {'success': True}
        return json_dumpb(ret)

    def render_OPTIONS(self, request: 'Request'):
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
                                                'chain': 'post_peerid',
                                                'target': {
                                                    'type': 'NetfilterLog',
                                                    'parameters': {
                                                        'msg': 'Test'
                                                    }
                                                },
                                                'match': {
                                                    'type': 'NetfilterMatchPeerId',
                                                    'parameters': {
                                                        'peer_id': 'f7397705bc07aabf6fc3f68de6605d93b560bc832d9ebbdfb0d3bd41e1f9480b'
                                                    }
                                                }
                                            },
                                            {
                                                'chain': 'post_peerid',
                                                'target': {
                                                    'type': 'NetfilterLog',
                                                    'parameters': {
                                                        'msg': 'Wat'
                                                    }
                                                },
                                                'match': {
                                                    'type': 'NetfilterMatchPeerId',
                                                    'parameters': {
                                                        'peer_id': 'f7397705bc07aabf6fc3f68de6605d93b560bc832d9ebbdfb0d3bd41e1f9480b'
                                                    }
                                                }
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
                                    'chain': 'post_peerid',
                                    'match': 'peer_id',
                                    'match_params': {
                                        'peer_id': 'f7397705bc07aabf6fc3f68de6605d93b560bc832d9ebbdfb0d3bd41e1f9480b'
                                    },
                                    'target': 'reject',
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
                                    'match': 'peer_id',
                                    'match_params': {
                                        'peer_id': 'f7397705bc07aabf6fc3f68de6605d93b560bc832d9ebbdfb0d3bd41e1f9480b'
                                    },
                                    'target': 'reject',
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