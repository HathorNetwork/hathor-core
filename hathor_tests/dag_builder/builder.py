# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from types import ModuleType

from mnemonic import Mnemonic

from hathor.dag_builder import DAGBuilder
from hathor.dag_builder.types import WalletFactoryType
from hathor.manager import HathorManager
from hathor.util import Random
from hathor.wallet import HDWallet
from hathor_tests.nanocontracts import test_blueprints
from hathor_tests.utils import GENESIS_SEED


class TestDAGBuilder:
    @staticmethod
    def create_random_hd_wallet(rng: Random) -> HDWallet:
        m = Mnemonic('english')
        words = m.to_mnemonic(rng.randbytes(32))
        hd = HDWallet(words=words)
        hd._manually_initialize()
        return hd

    @staticmethod
    def from_manager(
        manager: HathorManager,
        genesis_words: str | None = None,
        wallet_factory: WalletFactoryType | None = None,
        blueprints_module: ModuleType | None = None
    ) -> DAGBuilder:
        """Create a DAGBuilder instance from a HathorManager instance."""
        return DAGBuilder.from_manager(
            manager=manager,
            genesis_words=genesis_words or GENESIS_SEED,
            wallet_factory=wallet_factory or (lambda: TestDAGBuilder.create_random_hd_wallet(manager.rng)),
            blueprints_module=blueprints_module or test_blueprints,
        )
