# Copyright 2026 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
