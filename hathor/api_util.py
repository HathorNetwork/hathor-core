def set_cors(request, method):
    request.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000')
    request.setHeader('Access-Control-Allow-Methods', method)
    request.setHeader('Access-Control-Allow-Headers', 'x-prototype-version,x-requested-with,content-type')
    request.setHeader('Access-Control-Max-Age', 604800)


def render_options(request):
    from twisted.web import server
    set_cors(request, 'GET, POST, OPTIONS')
    request.setHeader(b'content-type', b'application/json; charset=utf-8')
    request.write(b'')
    request.finish()
    return server.NOT_DONE_YET
