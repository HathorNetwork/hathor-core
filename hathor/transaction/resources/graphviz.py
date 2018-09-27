from twisted.web import resource
from hathor.api_util import set_cors


class GraphvizResource(resource.Resource):
    """ Implements a web server API that returns a visualization of the DAG using Graphviz.

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the tx_storage
        self.manager = manager

    def render_GET(self, request):
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
        }

        dotformat = 'pdf'
        if b'format' in request.args:
            dotformat = request.args[b'format'][0].decode('utf-8')

        weight = False
        if b'weight' in request.args:
            weight = self.parseBoolArg(request.args[b'weight'][0].decode('utf-8'))

        acc_weight = False
        if b'acc_weight' in request.args:
            acc_weight = self.parseBoolArg(request.args[b'acc_weight'][0].decode('utf-8'))

        dot = self.manager.tx_storage.graphviz(format=dotformat, weight=weight, acc_weight=acc_weight)
        request.setHeader(b'content-type', contenttype[dotformat])
        return dot.pipe()

    def parseBoolArg(self, arg):
        """Returns a boolean object for the given parameter

        :rtype: bool
        """
        if not arg:
            return False
        if arg in ['false', 'False', '0']:
            return False

        return True
