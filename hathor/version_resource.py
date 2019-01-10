import json

from twisted.web import resource

import hathor
from hathor.api_util import set_cors


class VersionResource(resource.Resource):
    """ Implements a web server API with POST to return the api version

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def render_GET(self, request):
        """ GET request for /version/ that returns the API version

            :rtype: string (json)
        """
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'GET')

        data = {
            'version': hathor.__version__,
        }
        return json.dumps(data, indent=4).encode('utf-8')
