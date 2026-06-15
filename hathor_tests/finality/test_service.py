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

import hashlib

from hathor.finality.crypto import FinalityValidatorSigner, bls_keygen, bls_pop_prove
from hathor.finality.fc import FinalityCertificate, Vote
from hathor.finality.finality_settings import FinalitySettings, FinalityValidatorSettings
from hathor.finality.pending_pool import PendingFinalityPool
from hathor.finality.service import FinalityService
from hathor.finality.stores import MemoryFinalityCertificateStore, MemoryFinalityPinStore
from hathor.simulator.utils import add_new_blocks, gen_new_tx
from hathor.transaction import Transaction
from hathor_tests import unittest
from hathor_tests.utils import add_blocks_unlock_reward


def _committee(n: int) -> tuple[FinalitySettings, list[FinalityValidatorSigner]]:
    signers, validators = [], []
    for i in range(n):
        sk = bls_keygen(hashlib.sha256(f'svc-{i}'.encode()).digest())
        signer = FinalityValidatorSigner(sk)
        signers.append(signer)
        validators.append(FinalityValidatorSettings(
            public_key=bytes(signer.public_key).hex(),
            pop=bytes(bls_pop_prove(sk)).hex(),
        ))
    return FinalitySettings(enabled=True, validators=tuple(validators)), signers


class _FinalityNetwork:
    """An in-process network of validator FinalityServices wired over a synchronous fake transport.

    The transport (de)serializes vertices through the shared tx storage, exactly like the real p2p
    handlers, so this also exercises Vote/FC/transaction serialization end-to-end.
    """

    def __init__(self, settings: FinalitySettings, signers: list[FinalityValidatorSigner], tx_storage) -> None:
        self.settings = settings
        self.tx_storage = tx_storage
        self.services: dict[int, FinalityService] = {}
        self.admitted: dict[int, list[bytes]] = {i: [] for i in range(len(signers))}
        for i, signer in enumerate(signers):
            self.services[i] = FinalityService(
                finality_settings=settings,
                pending_pool=PendingFinalityPool(),
                certificate_store=MemoryFinalityCertificateStore(),
                transport=_Transport(self, i),
                admit_certified_tx=self._make_admit(i),
                is_feature_active=lambda: True,
                signer=signer,
                pin_store=MemoryFinalityPinStore(),
            )

    def _make_admit(self, owner: int):
        def admit(tx: Transaction) -> bool:
            self.admitted[owner].append(tx.hash)
            return True
        return admit

    def deserialize(self, tx_bytes: bytes) -> Transaction:
        tx = Transaction.create_from_struct(tx_bytes, storage=self.tx_storage)
        tx.storage = self.tx_storage
        return tx


class _Transport:
    def __init__(self, network: _FinalityNetwork, owner: int) -> None:
        self._network = network
        self._owner = owner

    def _others(self):
        return [(j, svc) for j, svc in self._network.services.items() if j != self._owner]

    def submit_to_validator(self, tx_bytes: bytes) -> None:
        target = 0 if self._owner != 0 else 1
        self._network.services[target].on_submit_finality_tx(self._network.deserialize(tx_bytes), source=self._owner)

    def flood_to_validators(self, tx_bytes: bytes, *, exclude=None) -> None:
        for _j, svc in self._others():
            svc.on_submit_finality_tx(self._network.deserialize(tx_bytes), source=self._owner)

    def flood_vote(self, vote_bytes: bytes, *, exclude=None) -> None:
        for _j, svc in self._others():
            svc.on_vote(Vote.from_bytes(vote_bytes), source=self._owner)

    def broadcast_certificate(self, tx_bytes: bytes, fc_bytes: bytes, *, exclude=None) -> None:
        for _j, svc in self._others():
            svc.on_certificate(
                self._network.deserialize(tx_bytes),
                FinalityCertificate.from_bytes(fc_bytes),
                source=self._owner,
            )


class FinalityServiceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('testnet')
        add_new_blocks(self.manager, 3, advance_clock=15)
        add_blocks_unlock_reward(self.manager)

    def _new_tx(self) -> Transaction:
        address = self.manager.wallet.get_unused_address(mark_as_used=True)
        return gen_new_tx(self.manager, address, 100)

    def test_honest_tx_reaches_quorum_and_is_admitted_everywhere(self) -> None:
        settings, signers = _committee(4)  # f = 1, quorum = 3
        network = _FinalityNetwork(settings, signers, self.manager.tx_storage)
        tx = self._new_tx()

        # Validator 0 receives the submission (as if from a client) and the gossip runs to completion.
        network.services[0].on_submit_finality_tx(tx, source=None)

        # Every validator has stored the certificate and admitted the transaction.
        for i in range(4):
            assert network.services[i]._certificates.has_certificate(tx.hash), f'validator {i} missing cert'
            assert tx.hash in network.admitted[i], f'validator {i} did not admit tx'

        # The stored certificate is a valid quorum certificate.
        fc = FinalityCertificate.from_bytes(network.services[0]._certificates.get_certificate(tx.hash))
        assert fc.verify(settings)

    def test_double_spend_never_certifies(self) -> None:
        settings, signers = _committee(4)
        network = _FinalityNetwork(settings, signers, self.manager.tx_storage)

        # Two transactions spending the same input(s): the second one conflicts with the first.
        tx1 = self._new_tx()
        tx2 = gen_new_tx(self.manager, self.manager.wallet.get_unused_address(mark_as_used=True), 100)
        # Force a real conflict: make tx2 spend tx1's inputs.
        tx2.inputs = tx1.inputs
        tx2.timestamp = tx1.timestamp + 1
        tx2.parents = tx1.parents
        self.manager.cpu_mining_service.resolve(tx2)
        assert tx1.hash != tx2.hash

        # Split the committee: half see tx1 first, half see tx2 first (each validator pins what it saw).
        network.services[0].on_submit_finality_tx(tx1, source=99)
        network.services[1].on_submit_finality_tx(tx1, source=99)
        network.services[2].on_submit_finality_tx(tx2, source=99)
        network.services[3].on_submit_finality_tx(tx2, source=99)

        # At most one of the two transactions can ever be certified (quorum intersection).
        certified = [
            tx.hash
            for tx in (tx1, tx2)
            for i in range(4)
            if network.services[i]._certificates.has_certificate(tx.hash)
        ]
        # tx1 and tx2 cannot both be certified.
        assert not (tx1.hash in certified and tx2.hash in certified)
