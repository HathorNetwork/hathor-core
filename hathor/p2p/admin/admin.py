"""Admin/status webpage for viewing p2p network state."""

import json
from telnetlib import Telnet  # Quick hack to talk to Hathor node

from flask import flash, Flask, render_template

from hathor.p2p.peer_id import PeerId

FLASK_PORT = 8080
TIMEOUT_SEC = 1


def server_get_peers(url='localhost', port=8000):
    """Retrieve a list of peers in JSON format from a server."""
    peer_id = PeerId()

    hello = {
        'id': peer_id.id,
        'pubKey': peer_id.get_public_key(),
        'endpoints': [],
        # TODO 'signature': signature,
    }

    # Connect to the server, handshake, and get the peers.
    # TODO: Use a more robust method. Improve on this simple telnet setup.
    # TODO: Use command string constants from protocol.py; don't hardcode.
    peers = []
    with Telnet(url, port) as tn:
        x = tn.read_until(b'HELLO', timeout=TIMEOUT_SEC)
        print(x)

        tn.write(b'HELLO ' + json.dumps(hello).encode())
        server_info = json.loads(tn.read_until(b'\n', TIMEOUT_SEC).decode().strip())
        print(server_info)

        tn.write(b'GET-PEERS {}\n')
        peers_str = tn.read_until(b'\n', TIMEOUT_SEC)
        print('peers-str: ' + peers_str.decode())
        try:
            peers = json.loads(peers_str.decode().strip())
        except Exception as e:
            flash('Error reading peers from server: %s' % e)

    if not peers:
        flash('No peers found.')

    return peers


def create_app():
    app = Flask(__name__)
    app.debug = True
    app.secret_key = 'Hathor!'
    app.config['SESSION_TYPE'] = 'filesystem'

    @app.route('/')
    def main():
        return render_template('main.html')

    @app.route('/connections')
    def connections():
        peers = server_get_peers()
        return render_template('connections.html', peers=peers)

    @app.route('/graph')
    def graph():
        return render_template('graph.html')

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(port=FLASK_PORT)
