# Copyright (c) Hathor Labs and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import unittest

from hathorlib.nanocontracts.on_chain_blueprint import Code, CodeKind, OnChainBlueprint


class OnChainBlueprintTestCase(unittest.TestCase):
    def _get_ocb(self):
        ocb = OnChainBlueprint()
        ocb.weight = 1
        ocb.timestamp = 123456
        ocb.nc_pubkey = b'\x020\xc1K\xb8\xc4fO>\xb7\x96a\xdeN\x96\x92\xcd\x1c' \
                        b'\xa8\xa3]\xfeZ\xf7}\x95\x99\xb0\x1cBE\xc8\x90'
        ocb.nc_signature = b'0F\x02!\x00\x9c\xfey\xb1C\x9eAJ\x9eU~\xe3\xaf\xfcQ'  \
                           b'\xf6\xf0`g\x1b0\xb6\xca\x1b\xed\x83:N\xa0\x98\xd2'   \
                           b'\xdf\x02!\x00\xbe\xf85\xf6O`\xfed`Ip\xe2a\xc4\x03vv' \
                           b'\xec\x94\ny?\xde\x90\xc3\x12\x9c\xd8\xdd\xd8\xe5\r'
        code = Code(CodeKind.PYTHON_ZLIB, b'')
        ocb.code = code
        return ocb

    def test_serialization(self):
        ocb = self._get_ocb()

        ocb_bytes = bytes(ocb)
        ocb2 = OnChainBlueprint.create_from_struct(ocb_bytes)
        self.assertEqual(ocb_bytes, bytes(ocb2))

        self.assertEqual(ocb.weight, ocb2.weight)
        self.assertEqual(ocb.timestamp, ocb2.timestamp)
        self.assertEqual(ocb.nc_pubkey, ocb2.nc_pubkey)
        self.assertEqual(ocb.nc_signature, ocb2.nc_signature)
        self.assertEqual(ocb.code.kind, ocb2.code.kind)
        self.assertEqual(ocb.code.data, ocb2.code.data)
