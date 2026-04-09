# Copyright (c) Hathor Labs and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import unittest

from hathorlib import Transaction
from hathorlib.headers import NanoHeader, VertexHeaderId
from hathorlib.headers.nano_header import NanoHeaderAction
from hathorlib.nanocontracts.types import NCActionType


class NCNanoContractTestCase(unittest.TestCase):
    def _get_nc(self) -> Transaction:
        nc = Transaction()
        nc.weight = 1
        nc.timestamp = 123456
        nano_header = NanoHeader(
            tx=nc,
            nc_seqnum=123,
            nc_actions=[
                NanoHeaderAction(
                    type=NCActionType.DEPOSIT,
                    token_index=0,
                    amount=123,
                ),
            ],
            nc_id=b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
            nc_method='initialize',
            # ['string', 1]
            nc_args_bytes=b'\x00\x06string\x00\x04\x00\x00\x00\x01',
            nc_address=bytes.fromhex('280ff02e7049b7b15356a1d8108d2d8cda79b65ddf84403239'),
            nc_script=bytes.fromhex('47304502206db7372dde8dfaac7364d6cd13517e3fc0d75fea09bc3c6a425e5607fcec3f93022100a'
                                    'aadfbdab62eaa65e2a6031ff04fccd283e9d653a80a858cb97dd101e5c689ae2102d6c0adc88c4e80'
                                    '8f1aa1ee0fbce19f082613c0603eeb90764702f859b55c615b')
        )
        nc.headers = [nano_header]
        return nc

    def test_serialization(self) -> None:
        nc = self._get_nc()

        nc_bytes = bytes(nc)
        nc2 = Transaction.create_from_struct(nc_bytes)
        self.assertEqual(nc_bytes, bytes(nc2))
        nano_header1 = nc.get_nano_header()
        nano_header2 = nc2.get_nano_header()
        assert isinstance(nano_header1, NanoHeader)
        assert isinstance(nano_header2, NanoHeader)

        self.assertEqual(nano_header1.nc_seqnum, nano_header2.nc_seqnum)
        self.assertEqual(nano_header1.nc_id, nano_header2.nc_id)
        self.assertEqual(nano_header1.nc_method, nano_header2.nc_method)
        self.assertEqual(nano_header1.nc_args_bytes, nano_header2.nc_args_bytes)
        self.assertEqual(nano_header1.nc_address, nano_header2.nc_address)
        self.assertEqual(nano_header1.nc_script, nano_header2.nc_script)
        self.assertEqual(nano_header1.nc_actions, nano_header2.nc_actions)

    def test_serialization_skip_signature(self) -> None:
        nc = self._get_nc()
        nano_header = nc.get_nano_header()
        sighash_bytes = nano_header.get_sighash_bytes()
        deserialized, buf = NanoHeader.deserialize(Transaction(), VertexHeaderId.NANO_HEADER.value + sighash_bytes)
        assert isinstance(nano_header, NanoHeader)
        assert isinstance(deserialized, NanoHeader)

        assert len(buf) == 0
        assert deserialized.nc_seqnum == nano_header.nc_seqnum
        assert deserialized.nc_id == nano_header.nc_id
        assert deserialized.nc_method == nano_header.nc_method
        assert deserialized.nc_args_bytes == nano_header.nc_args_bytes
        assert deserialized.nc_actions == nano_header.nc_actions
        assert deserialized.nc_address == nano_header.nc_address
        assert deserialized.nc_script == b''
