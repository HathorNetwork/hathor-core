#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import hashlib

from hathor import HATHOR_TOKEN_UID, Blueprint, Context, ContractId, __version__, public
from hathor.nanocontracts.nc_dump import BlockDump, ContractDump, NCDump, NCDumper
from hathor.nanocontracts.nc_types import BytesNCType
from hathor.nanocontracts.storage import NCBlockStorage
from hathor.nanocontracts.storage.maybedeleted_nc_type import MaybeDeletedNCType
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.serialization import Serializer
from hathor.transaction import Block, Transaction
from hathor.transaction.token_info import TokenDescription, TokenVersion
from hathor.util import not_none
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    my_int: int

    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        self.my_int = 123

    @public
    def create_token(self, ctx: Context) -> None:
        self.syscall.create_deposit_token(
            token_name='Token A',
            token_symbol='TKA',
            amount=1000,
            salt=b'salt',
        )


class TestNCDump(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.nc_dumper = NCDumper(settings=self._settings, tx_storage=self.manager.tx_storage)

        serializer = Serializer.build_bytes_serializer()
        MaybeDeletedNCType(BytesNCType()).serialize(serializer, self.blueprint_id)
        self.serialized_blueprint_id = bytes(serializer.finalize())

    def test_empty(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..10]
        ''')

        artifacts.propagate_with(self.manager)
        result = self.nc_dumper.get_nc_dump()

        assert result == NCDump(
            version=__version__,
            network='unittests',
            blocks={}
        )

    # TODO: mark visited contract root ids?

    def test_initialize(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1.nc_seqnum = 9
            nc1.nc_deposit = 123 HTR

            nc1 <-- b11
        ''')

        artifacts.propagate_with(self.manager)
        b11 = artifacts.get_typed_vertex('b11', Block)
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)

        b11_root_id = not_none(b11.get_metadata().nc_block_root_id)
        b11_storage = self.manager.get_nc_block_storage(b11)
        nc1_root_id = b11_storage.get_contract_root_id(nc1.hash)

        nc1_address = nc1.get_nano_header().nc_address

        result = self.nc_dumper.get_nc_dump()

        assert result == NCDump(
            version=__version__,
            network='unittests',
            blocks={
                b11_root_id: BlockDump(
                    hash=b11.hash,
                    height=11,
                    contracts={
                        nc1_root_id: ContractDump(
                            hash=nc1.hash,
                            attrs={
                                hashlib.sha256(b'my_int').digest(): bytes.fromhex('01fb00'),
                            },
                            balances={
                                HATHOR_TOKEN_UID: bytes.fromhex('01fb000000')
                            },
                            metadata={
                                hashlib.sha256(b'blueprint_id').digest(): self.serialized_blueprint_id,
                            },
                        )
                    },
                    tokens={},
                    addresses={
                        nc1_address: bytes.fromhex('09'),
                    },
                )
            }
        )

    def test_two_blocks_single_contract(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()

            nc1 <-- b11
        ''')

        artifacts.propagate_with(self.manager)
        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)

        b11_root_id = not_none(b11.get_metadata().nc_block_root_id)
        b12_root_id = not_none(b12.get_metadata().nc_block_root_id)

        b11_storage = self.manager.get_nc_block_storage(b11)
        b12_storage = self.manager.get_nc_block_storage(b12)
        nc1_root_id = b11_storage.get_contract_root_id(nc1.hash)
        assert nc1_root_id == b12_storage.get_contract_root_id(nc1.hash)

        nc1_address = nc1.get_nano_header().nc_address

        result = self.nc_dumper.get_nc_dump()

        nc1_dump = ContractDump(
            hash=nc1.hash,
            attrs={
                hashlib.sha256(b'my_int').digest(): bytes.fromhex('01fb00'),
            },
            balances={},
            metadata={
                hashlib.sha256(b'blueprint_id').digest(): self.serialized_blueprint_id,
            },
        )

        assert result == NCDump(
            version=__version__,
            network='unittests',
            blocks={
                b12_root_id: BlockDump(
                    hash=b12.hash,
                    height=12,
                    contracts={
                        nc1_root_id: nc1_dump,
                    },
                    tokens={},
                    addresses={
                        nc1_address: bytes.fromhex('00'),
                    },
                ),
                b11_root_id: BlockDump(
                    hash=b11.hash,
                    height=11,
                    contracts={
                        nc1_root_id: nc1_dump,
                    },
                    tokens={},
                    addresses={
                        nc1_address: bytes.fromhex('00'),
                    },
                ),
            }
        )

    def test_create_token(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1.nc_deposit = 123 HTR

            nc2.nc_id = nc1
            nc2.nc_method = create_token()

            nc1 <-- b11
            nc2 <-- b12
        ''')

        artifacts.propagate_with(self.manager)
        b11, b12 = artifacts.get_typed_vertices(('b11', 'b12'), Block)
        nc1, nc2 = artifacts.get_typed_vertices(('nc1', 'nc2'), Transaction)

        b11_root_id = not_none(b11.get_metadata().nc_block_root_id)
        b12_root_id = not_none(b12.get_metadata().nc_block_root_id)

        b11_storage = self.manager.get_nc_block_storage(b11)
        b12_storage = self.manager.get_nc_block_storage(b12)
        nc1_root_id_b11 = b11_storage.get_contract_root_id(nc1.hash)
        nc1_root_id_b12 = b12_storage.get_contract_root_id(nc1.hash)

        nc1_address = nc1.get_nano_header().nc_address
        nc2_address = nc2.get_nano_header().nc_address

        tka_hash = derive_child_token_id(ContractId(nc1.hash), 'TKA', salt=b'salt')
        tka_description = TokenDescription(
            token_id=tka_hash,
            token_name='Token A',
            token_symbol='TKA',
            token_version=TokenVersion.DEPOSIT,
        )
        tka_description_bytes = NCBlockStorage._TOKEN_DESCRIPTION_NC_TYPE.to_bytes(tka_description)

        result = self.nc_dumper.get_nc_dump()

        assert result == NCDump(
            version=__version__,
            network='unittests',
            blocks={
                b12_root_id: BlockDump(
                    hash=b12.hash,
                    height=12,
                    contracts={
                        nc1_root_id_b12: ContractDump(
                            hash=nc1.hash,
                            attrs={
                                hashlib.sha256(b'my_int').digest(): bytes.fromhex('01fb00'),
                            },
                            balances={
                                HATHOR_TOKEN_UID: bytes.fromhex('01f1000000'),
                                tka_hash: bytes.fromhex('01e8070101')
                            },
                            metadata={
                                hashlib.sha256(b'blueprint_id').digest(): self.serialized_blueprint_id,
                            },
                        ),
                    },
                    tokens={
                        tka_hash: tka_description_bytes
                    },
                    addresses={
                        nc1_address: bytes.fromhex('00'),
                        nc2_address: bytes.fromhex('00'),
                    },
                ),
                b11_root_id: BlockDump(
                    hash=b11.hash,
                    height=11,
                    contracts={
                        nc1_root_id_b11: ContractDump(
                            hash=nc1.hash,
                            attrs={
                                hashlib.sha256(b'my_int').digest(): bytes.fromhex('01fb00'),
                            },
                            balances={
                                HATHOR_TOKEN_UID: bytes.fromhex('01fb000000')
                            },
                            metadata={
                                hashlib.sha256(b'blueprint_id').digest(): self.serialized_blueprint_id,
                            },
                        ),
                    },
                    tokens={},
                    addresses={
                        nc1_address: bytes.fromhex('00'),
                    },
                ),
            }
        )
