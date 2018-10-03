from twisted.web import resource, server
from hathor.api_util import set_cors

import json
import os


class ProfilerResource(resource.Resource):
    """ Implements a web server API with POST to lock the wallet

    You must run with option `--status <PORT>`.
    """
    isLeaf = True

    def __init__(self, manager):
        # Important to have the manager so we can know the wallet
        self.manager = manager

    def gen_dump_filename(self):
        for i in range(1, 100):
            dump_filename = 'profiles/profile{:03d}.prof'.format(i)
            if not os.path.exists(dump_filename):
                return dump_filename
        else:
            raise Exception('Unable to generate dump filename')

    def render_POST(self, request):
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        set_cors(request, 'POST')

        ret = {'success': True}

        if b'start' in request.uri:
            self.manager.start_profiler()

        elif b'stop' in request.uri:
            dump_filename = self.gen_dump_filename()
            self.manager.stop_profiler(save_to=dump_filename)
            ret['saved_to'] = dump_filename

        else:
            ret['success'] = False

        return json.dumps(ret, indent=4).encode('utf-8')

    def render_OPTIONS(self, request):
        set_cors(request, 'POST, OPTIONS')
        request.setHeader(b'content-type', b'application/json; charset=utf-8')
        request.write('')
        request.finish()
        return server.NOT_DONE_YET
