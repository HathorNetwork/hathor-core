#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import pytest
from cryptography.exceptions import InvalidSignature

from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.exception import NCInvalidSignature
from hathor.nanocontracts.types import BlueprintId, VertexId
from hathor.transaction import Transaction
from hathor.util import not_none
from hathor.wallet import KeyPair
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TestRestrictedOCB(unittest.TestCase):
    def test_ocb_address_allowed(self) -> None:
        manager = self.create_peer_from_builder(self.get_builder())
        dag_builder = TestDAGBuilder.from_manager(manager)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"

            nc.nc_id = ocb
            nc.nc_method = initialize(0)

            ocb <-- b11
            b11 < nc

            ocb.ocb_code = test_blueprint1.py, TestBlueprint1
        """)

        artifacts.propagate_with(manager)
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)
        nc = artifacts.get_typed_vertex('nc', Transaction)

        assert nc.is_nano_contract()

        assert ocb.get_blueprint_class().__name__ == 'TestBlueprint1'
        assert nc.get_nano_header().nc_id == ocb.hash
        blueprint_class = manager.tx_storage.get_blueprint_class(BlueprintId(VertexId(ocb.hash)))
        assert blueprint_class.__name__ == 'TestBlueprint1'

    def test_ocb_address_not_allowed(self) -> None:
        manager = self.create_peer_from_builder(self.get_builder())
        dag_builder = TestDAGBuilder.from_manager(manager)
        password = b'abc'
        key_pair = KeyPair.create(password=password)

        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb.ocb_private_key = "{not_none(key_pair.private_key_bytes).hex()}"
            ocb.ocb_password = "{password.hex()}"

            ocb.ocb_code = test_blueprint1.py, TestBlueprint1
            dummy < ocb
        """)

        artifacts.propagate_with(manager, up_to='dummy')

        with pytest.raises(Exception) as e:
            artifacts.propagate_with(manager, up_to='ocb')

        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == (
            f'full validation failed: nc_pubkey with address {key_pair.address} is not allowed'
        )

    def test_ocb_unrestricted(self) -> None:
        builder = self.get_builder() \
            .set_settings(self._settings.model_copy(update={'NC_ON_CHAIN_BLUEPRINT_RESTRICTED': False}))
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)
        password = b'abc'
        key_pair = KeyPair.create(password=password)

        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb.ocb_private_key = "{not_none(key_pair.private_key_bytes).hex()}"
            ocb.ocb_password = "{password.hex()}"

            nc.nc_id = ocb
            nc.nc_method = initialize(0)

            ocb <-- b11
            b11 < nc

            ocb.ocb_code = test_blueprint1.py, TestBlueprint1
        """)

        artifacts.propagate_with(manager)
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)
        nc = artifacts.get_typed_vertex('nc', Transaction)

        assert nc.is_nano_contract()

        assert ocb.get_blueprint_class().__name__ == 'TestBlueprint1'
        assert nc.get_nano_header().nc_id == ocb.hash
        blueprint_class = manager.tx_storage.get_blueprint_class(BlueprintId(VertexId(ocb.hash)))
        assert blueprint_class.__name__ == 'TestBlueprint1'

    def test_ocb_invalid_pubkey(self) -> None:
        builder = self.get_builder() \
            .set_settings(self._settings.model_copy(update={'NC_ON_CHAIN_BLUEPRINT_RESTRICTED': False}))
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"

            ocb.ocb_code = test_blueprint1.py, TestBlueprint1
            dummy < ocb
        """)

        artifacts.propagate_with(manager, up_to='dummy')
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)

        # Remove a byte to make the pubkey invalid
        ocb.nc_pubkey = ocb.nc_pubkey[:-1]

        with pytest.raises(Exception) as e:
            artifacts.propagate_with(manager, up_to='ocb')

        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == 'full validation failed: nc_pubkey is not a public key'

    def test_ocb_invalid_signature(self) -> None:
        manager = self.create_peer_from_builder(self.get_builder())
        dag_builder = TestDAGBuilder.from_manager(manager)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"

            ocb.ocb_code = test_blueprint1.py, TestBlueprint1
            dummy < ocb
        """)

        artifacts.propagate_with(manager, up_to='dummy')
        ocb = artifacts.get_typed_vertex('ocb', OnChainBlueprint)

        # Remove a byte to make the signature invalid
        ocb.nc_signature = ocb.nc_signature[:-1]

        with pytest.raises(Exception) as e:
            artifacts.propagate_with(manager, up_to='ocb')

        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert isinstance(e.value.__cause__.__cause__, NCInvalidSignature)
        assert isinstance(e.value.__cause__.__cause__.__cause__, InvalidSignature)
