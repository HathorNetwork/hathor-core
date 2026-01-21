# Copyright (c) Hathor Labs and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import base64
import unittest
from unittest.mock import MagicMock

from hathorlib.utils import get_address_b58_from_public_key, get_public_key_from_bytes_compressed


class HathorUtilsTestCase(unittest.TestCase):
    def test_address_from_pubkey(self):
        pubkey_bytes = base64.b64decode("AzDv7fmrf98FfyThpHcHmuEM80vQCi04pnMohBvItqY8")
        pubkey = get_public_key_from_bytes_compressed(pubkey_bytes)
        address_b58 = get_address_b58_from_public_key(pubkey)
        self.assertEqual('HURjYEBdMPtk7kVYBKyHCWc3HAvjrx3unT', address_b58)


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)
