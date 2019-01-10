""" Generates a random PeerId and print it to stdout.
It may be used to testing purposes.
"""

import json


def main() -> None:
    from hathor.p2p.peer_id import PeerId

    peer_id = PeerId()
    data = peer_id.to_json(include_private_key=True)
    txt = json.dumps(data, indent=4)
    print(txt)
