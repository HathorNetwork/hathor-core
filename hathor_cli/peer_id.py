# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

""" Generates a random Peer and print it to stdout.
It may be used to testing purposes.
"""

import json


def main() -> None:
    from hathor.p2p.peer import PrivatePeer

    peer = PrivatePeer.auto_generated()
    data = peer.to_json_private()
    txt = json.dumps(data, indent=4)
    print(txt)
