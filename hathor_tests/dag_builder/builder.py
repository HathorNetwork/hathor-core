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

from types import ModuleType

from mnemonic import Mnemonic

from hathor.dag_builder import DAGBuilder
from hathor.dag_builder.types import WalletFactoryType
from hathor.manager import HathorManager
from hathor.util import Random
from hathor.wallet import BaseWallet, HDWallet
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
        wallet_factory: WalletFactoryType | dict[str, BaseWallet] | None = None,
        blueprints_module: ModuleType | None = None,
        deterministic: bool = False,
    ) -> DAGBuilder:
        """Create a DAGBuilder instance from a HathorManager instance."""
        if wallet_factory is None:
            wallet_factory = lambda: TestDAGBuilder.create_random_hd_wallet(manager.rng)

        return DAGBuilder.from_manager(
            manager=manager,
            genesis_words=genesis_words or GENESIS_SEED,
            wallet_factory=wallet_factory,
            blueprints_module=blueprints_module or test_blueprints,
            deterministic=deterministic,
        )
