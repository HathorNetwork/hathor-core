import json

from twisted.internet import threads
from twisted.web import resource
from twisted.web.http import Request

from hathor.api_util import set_cors, validate_tx_hash
from hathor.cli.openapi_files.register import register_resource
from hathor.conf import HathorSettings
from hathor.graphviz import GraphvizVisualizer

settings = HathorSettings()


@register_resource
class GraphvizResource(resource.Resource):
    """ Implements a web server API that returns a visualization of the DAG using Graphviz.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def _render_GET_thread(self, request: Request) -> bytes:
        """ GET request /graphviz/
            Expects 'format' parameter in request to set the content-type of the graph
            Format options are 'pdf', 'png' and 'jpg'. Default format is 'pdf'
            Returns the file
        """
        set_cors(request, 'GET')

        contenttype = {
            'pdf': b'application/pdf',
            'png': b'image/png',
            'jpg': b'image/jpeg',
            'dot': b'application/dot',
        }

        dotformat = 'pdf'
        if b'format' in request.args:
            dotformat = request.args[b'format'][0].decode('utf-8')

        tx_storage = self.manager.tx_storage

        if b'tx' in request.args:
            # Getting tx neightborhood
            tx_hex = request.args[b'tx'][0].decode('utf-8')
            success, message = validate_tx_hash(tx_hex, tx_storage)
            if not success:
                return json.dumps({'success': False, 'message': message}, indent=4).encode('utf-8')
            else:
                graph_type = request.args[b'graph_type'][0].decode('utf-8')
                max_level = int(request.args[b'max_level'][0])
                if max_level > settings.MAX_GRAPH_LEVEL:
                    return json.dumps({
                        'success': False,
                        'message': 'Graph max level is {}'.format(settings.MAX_GRAPH_LEVEL)
                    }, indent=4).encode('utf-8')
                tx = tx_storage.get_transaction(bytes.fromhex(tx_hex))

                graphviz = GraphvizVisualizer(tx_storage)
                dot = graphviz.tx_neighborhood(tx, format=dotformat, max_level=max_level, graph_type=graph_type)

        else:
            weight = False
            if b'weight' in request.args:
                weight = self.parseBoolArg(request.args[b'weight'][0].decode('utf-8'))

            acc_weight = False
            if b'acc_weight' in request.args:
                acc_weight = self.parseBoolArg(request.args[b'acc_weight'][0].decode('utf-8'))

            include_verifications = True
            if b'verifications' in request.args:
                include_verifications = self.parseBoolArg(request.args[b'verifications'][0].decode('utf-8'))

            include_funds = False
            if b'funds' in request.args:
                include_funds = self.parseBoolArg(request.args[b'funds'][0].decode('utf-8'))

            only_blocks = False
            if b'only_blocks' in request.args:
                only_blocks = self.parseBoolArg(request.args[b'only_blocks'][0].decode('utf-8'))

            graphviz = GraphvizVisualizer(tx_storage)
            graphviz.include_verifications = include_verifications
            graphviz.include_funds = include_funds
            graphviz.only_blocks = only_blocks
            graphviz.show_weight = weight
            graphviz.show_acc_weight = acc_weight
            dot = graphviz.dot(format=dotformat)

            if dotformat == 'dot':
                request.setHeader(b'content-type', contenttype[dotformat])
                return str(dot).encode('utf-8')

        request.setHeader(b'content-type', contenttype[dotformat])
        return dot.pipe()

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

    def parseBoolArg(self, arg: str) -> bool:
        """Returns a boolean object for the given parameter

        :rtype: bool
        """
        if not arg:
            return False
        if arg in ['false', 'False', '0']:
            return False

        return True


GraphvizResource.openapi = {
    '/graphviz': {
        'get': {
            'tags': ['transaction'],
            'operationId': 'graphviz',
            'summary': 'Dashboard of transactions',
            'description': ('Returns the generated file with the graph in the format requested.'
                            'Can be the full graph of the neighborhood graph of a transaction.'),
            'parameters': [
                {
                    'name': 'format',
                    'in': 'query',
                    'description': 'Format of the returned file',
                    'required': True,
                    'schema': {
                        'type': 'string'
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
                    'name': 'funds',
                    'in': 'query',
                    'description': 'If we will generate the network graph or the funds graph',
                    'required': False,
                    'schema': {
                        'type': 'boolean'
                    }
                },
                {
                    'name': 'tx',
                    'in': 'query',
                    'description': 'Id of the transaction or block to generate the neighborhood graph',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'graph_type',
                    'in': 'query',
                    'description': ('Type of the graph in case of a neighborhood graph.'
                                    'Can be either "verification" or "funds"'),
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'max_level',
                    'in': 'query',
                    'description': ('How many levels the neighbor can appear in the graph.'
                                    'Max level is {}'.format(settings.MAX_GRAPH_LEVEL)),
                    'required': False,
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
                                },
                                'error': {
                                    'summary': 'Error',
                                    'value': {
                                        'success': False,
                                        'message': 'Graph max level is 10'
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
