#  Copyright 2023 Hathor Labs
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

from typing import NamedTuple

from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction.storage import TransactionStorage
from hathor.verification.block_verifier import BlockVerifier
from hathor.verification.merge_mined_block_verifier import MergeMinedBlockVerifier
from hathor.verification.nano_header_verifier import NanoHeaderVerifier
from hathor.verification.on_chain_blueprint_verifier import OnChainBlueprintVerifier
from hathor.verification.poa_block_verifier import PoaBlockVerifier
from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
from hathor.verification.transaction_verifier import TransactionVerifier
from hathor.verification.transfer_header_verifier import TransferHeaderVerifier
from hathor.verification.vertex_verifier import VertexVerifier


class VertexVerifiers(NamedTuple):
    """A group of verifier instances, one for each vertex type."""
    vertex: VertexVerifier
    block: BlockVerifier
    merge_mined_block: MergeMinedBlockVerifier
    poa_block: PoaBlockVerifier
    tx: TransactionVerifier
    token_creation_tx: TokenCreationTransactionVerifier
    nano_header: NanoHeaderVerifier
    transfer_header: TransferHeaderVerifier
    on_chain_blueprint: OnChainBlueprintVerifier

    @classmethod
    def create_defaults(
        cls,
        *,
        reactor: Reactor,
        settings: HathorSettings,
        daa: DifficultyAdjustmentAlgorithm,
        feature_service: FeatureService,
        tx_storage: TransactionStorage,
    ) -> 'VertexVerifiers':
        """
        Create a VertexVerifiers instance using the default verifier for each vertex type,
        from all required dependencies.
        """
        vertex_verifier = VertexVerifier(reactor=reactor, settings=settings, feature_service=feature_service)

        return cls.create(
            reactor=reactor,
            settings=settings,
            vertex_verifier=vertex_verifier,
            daa=daa,
            feature_service=feature_service,
            tx_storage=tx_storage,
        )

    @classmethod
    def create(
        cls,
        *,
        reactor: Reactor,
        settings: HathorSettings,
        vertex_verifier: VertexVerifier,
        daa: DifficultyAdjustmentAlgorithm,
        feature_service: FeatureService,
        tx_storage: TransactionStorage,
    ) -> 'VertexVerifiers':
        """
        Create a VertexVerifiers instance using a custom vertex_verifier.
        """
        block_verifier = BlockVerifier(
            settings=settings,
            daa=daa,
            feature_service=feature_service,
            tx_storage=tx_storage,
        )
        merge_mined_block_verifier = MergeMinedBlockVerifier(settings=settings, feature_service=feature_service)
        poa_block_verifier = PoaBlockVerifier(settings=settings)
        tx_verifier = TransactionVerifier(settings=settings, daa=daa, feature_service=feature_service)
        token_creation_tx_verifier = TokenCreationTransactionVerifier(settings=settings)
        nano_header_verifier = NanoHeaderVerifier(settings=settings, tx_storage=tx_storage)
        transfer_header_verifier = TransferHeaderVerifier(settings=settings, tx_storage=tx_storage)
        on_chain_blueprint_verifier = OnChainBlueprintVerifier(settings=settings)

        return VertexVerifiers(
            vertex=vertex_verifier,
            block=block_verifier,
            merge_mined_block=merge_mined_block_verifier,
            poa_block=poa_block_verifier,
            tx=tx_verifier,
            token_creation_tx=token_creation_tx_verifier,
            nano_header=nano_header_verifier,
            transfer_header=transfer_header_verifier,
            on_chain_blueprint=on_chain_blueprint_verifier,
        )
