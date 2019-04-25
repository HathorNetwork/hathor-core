import json
from enum import Enum
from typing import Union

from twisted.internet import threads
from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors, validate_tx_hash
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings
from hathor.graphviz import GraphvizVisualizer

settings = HathorSettings()


class FileFormat(Enum):
    PDF = 'pdf'
    PNG = 'png'
    JPG = 'jpg'
    DOT = 'dot'

    @property
    def content_type(self) -> bytes:
        """ Value to use in Content-Type headers"""
        return {
            FileFormat.PDF: b'application/pdf',
            FileFormat.PNG: b'image/png',
            FileFormat.JPG: b'image/jpeg',
            FileFormat.DOT: b'application/dot',
        }[self]

    @property
    def dot(self) -> str:
        """ Value to pass to Graphviz"""
        return self.value


class _BaseGraphvizResource(resource.Resource):
    isLeaf = True

    def __init__(self, manager, *, format: Union[FileFormat, str]):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager
        self.format: FileFormat = FileFormat(format)

    def render_GET(self, request):
        deferred = threads.deferToThread(self._render_GET_thread, request)
        deferred.addCallback(self._cb_tx_resolve, request)
        deferred.addErrback(self._err_tx_resolve, request)

        from twisted.web.server import NOT_DONE_YET
        return NOT_DONE_YET

    def _cb_tx_resolve(self, result, request):
        """ Called when `_render_GET_thread` finishes
        """
        request.write(result)
        request.finish()

    def _err_tx_resolve(self, reason, request):
        """ Called when an error occur in `_render_GET_thread`
        """
        request.processingFailed(reason)


@register_resource
class GraphvizFullResource(_BaseGraphvizResource):
    """ Implements a web server API that returns a visualization of the full DAG using Graphviz.

    You must run with option `--status <PORT>`.
    """

    def _render_GET_thread(self, request: Request) -> bytes:
        """ GET request /graphviz/full.{format}
            Returns the rendered graph file
        """
        set_cors(request, 'GET')

        tx_storage = self.manager.tx_storage

        graphviz = GraphvizVisualizer(tx_storage)
        if b'weight' in request.args:
            graphviz.show_weight = self.parse_bool_arg(request.args[b'weight'][0].decode('utf-8'))
        if b'acc_weight' in request.args:
            graphviz.show_acc_weight = self.parse_bool_arg(request.args[b'acc_weight'][0].decode('utf-8'))
        if b'verifications' in request.args:
            graphviz.include_verifications = self.parse_bool_arg(request.args[b'verifications'][0].decode('utf-8'))
        if b'funds' in request.args:
            graphviz.include_funds = self.parse_bool_arg(request.args[b'funds'][0].decode('utf-8'))
        if b'only_blocks' in request.args:
            graphviz.only_blocks = self.parse_bool_arg(request.args[b'only_blocks'][0].decode('utf-8'))
        dot = graphviz.dot(format=self.format.dot)

        request.setHeader(b'content-type', self.format.content_type)
        if self.format is FileFormat.DOT:
            return str(dot).encode('utf-8')
        return dot.pipe()

    def parse_bool_arg(self, arg: str) -> bool:
        """Returns a boolean object for the given parameter

        :rtype: bool
        """
        if not arg:
            return False
        if arg in ['false', 'False', '0']:
            return False
        return True


GraphvizFullResource.openapi = {
    '/graphviz/full.{format}': {
        'x-visibility': 'private',
        'get': {
            'tags': ['transaction'],
            'operationId': 'graphviz',
            'summary': 'Dashboard of transactions',
            'description': 'Returns the generated file with the graph of the full DAG in the format requested.',
            'parameters': [
                {
                    'name': 'format',
                    'in': 'path',
                    'description': 'Format of the returned file',
                    'required': True,
                    'schema': {
                        'type': 'string',
                        'enum': [
                            'pdf',
                            'png',
                            'jpg',
                            'dot'
                        ]
                    }
                },
                {
                    'name': 'weight',
                    'in': 'query',
                    'description': 'If we will show the weight',
                    'required': False,
                    'schema': {
                        'type': 'boolean'
                    }
                },
                {
                    'name': 'acc_weight',
                    'in': 'query',
                    'description': 'If we will show the accumulated weight',
                    'required': False,
                    'schema': {
                        'type': 'boolean'
                    }
                },
                {
                    'name': 'verifications',
                    'in': 'query',
                    'description': 'Wether to show the verifications graph',
                    'required': False,
                    'schema': {
                        'type': 'boolean'
                    }
                },
                {
                    'name': 'funds',
                    'in': 'query',
                    'description': 'If we will generate the network graph or the funds graph',
                    'required': False,
                    'schema': {
                        'type': 'boolean'
                    }
                },
                {
                    'name': 'only_blocks',
                    'in': 'query',
                    'description': 'Only show blocks, hides transactions',
                    'required': False,
                    'schema': {
                        'type': 'boolean'
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
                                    'value': {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


@register_resource
class GraphvizNeighboursResource(_BaseGraphvizResource):
    """ Implements a web server API that returns a visualization of a tx neighbourhood using Graphviz.

    You must run with option `--status <PORT>`.
    """

    def _render_GET_thread(self, request: Request) -> bytes:
        """ GET request /graphviz/neighbours.{format}
            Returns the rendered graph file
        """
        set_cors(request, 'GET')

        tx_storage = self.manager.tx_storage

        tx_hex = request.args[b'tx'][0].decode('utf-8')
        success, message = validate_tx_hash(tx_hex, tx_storage)
        if not success:
            return json.dumps({'success': False, 'message': message}, indent=4).encode('utf-8')

        graph_type = request.args[b'graph_type'][0].decode('utf-8')
        max_level = min(int(request.args[b'max_level'][0]), settings.MAX_GRAPH_LEVEL)
        tx = tx_storage.get_transaction(bytes.fromhex(tx_hex))

        graphviz = GraphvizVisualizer(tx_storage)
        dot = graphviz.tx_neighborhood(tx, format=self.format.dot, max_level=max_level, graph_type=graph_type)

        request.setHeader(b'content-type', self.format.content_type)
        if self.format is FileFormat.DOT:
            return str(dot).encode('utf-8')
        return dot.pipe()


GraphvizNeighboursResource.openapi = {
    '/graphviz/neighbours.{format}': {
        'x-visibility': 'public',
        'x-path-params-regex': {
            'format': 'dot',  # technically it should be '.*' or '(dot|png|pdf|jpg)', but 'dot' hides other formats
        },
        'x-rate-limit': {
            'global': [
                {
                    'rate': '100r/s'
                }
            ],
            'per-ip': [
                {
                    'rate': '1r/s'
                }
            ]
        },
        'get': {
            'tags': ['transaction'],
            'operationId': 'graphviz',
            'summary': 'Dashboard of transactions',
            'description': 'Returns the generated file with the graph of neighbours of a tx in the format requested.',
            'parameters': [
                {
                    'name': 'format',
                    'in': 'path',
                    'description': 'Format of the returned file',
                    'required': True,
                    'schema': {
                        'type': 'string',
                        'enum': [
                            'pdf',
                            'png',
                            'jpg',
                            'dot'
                        ]
                    }
                },
                {
                    'name': 'tx',
                    'in': 'query',
                    'description': 'Id of the transaction or block to generate the neighborhood graph',
                    'required': True,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'graph_type',
                    'in': 'query',
                    'description': 'Type of the graph in case of a neighborhood graph.',
                    'required': True,
                    'schema': {
                        'type': 'string',
                        'enum': [
                            'verification',
                            'funds'
                        ]
                    }
                },
                {
                    'name': 'max_level',
                    'in': 'query',
                    'description': ('How many levels the neighbor can appear in the graph.'
                                    'Max level is {}'.format(settings.MAX_GRAPH_LEVEL)),
                    'required': True,
                    'schema': {
                        'type': 'int'
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
                                    'value': {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
