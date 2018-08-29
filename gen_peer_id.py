# encoding: utf-8
""" Generates a random PeerId and print it to stdout.
It may be used to testing purposes.
"""

from hathor.p2p.peer_id import PeerId

import json


if __name__ == '__main__':
    peer_id = PeerId()
    data = peer_id.to_json(include_private_key=True)
    txt = json.dumps(data, indent=4)
    print(txt)
