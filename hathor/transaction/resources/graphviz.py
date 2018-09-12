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
        set_cors(request, 'GET')

        contenttype = {
            'pdf': b'application/pdf',
            'png': b'image/png',
            'jpg': b'image/jpeg',
        }

        dotformat = 'pdf'
        if b'format' in request.args:
            dotformat = request.args[b'format'][0].decode('utf-8')

        dot = self.manager.tx_storage.graphviz(format=dotformat)
        request.setHeader(b'content-type', contenttype[dotformat])
        return dot.pipe()
