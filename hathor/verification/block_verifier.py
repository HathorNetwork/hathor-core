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

from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import BlockIsMissingSignal, BlockIsSignaling, FeatureService
from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Block
from hathor.transaction.exceptions import (
    BlockMustSignalError,
    BlockWithInputs,
    BlockWithTokensError,
    InvalidBlockReward,
    RewardLocked,
    TransactionDataError,
    WeightError,
)
from hathor.verification.vertex_verifier import VertexVerifier

cpu = get_cpu_profiler()


class BlockVerifier(VertexVerifier):
    __slots__ = ('_feature_service', )

    def __init__(
        self,
        *,
        settings: HathorSettings,
        daa: DifficultyAdjustmentAlgorithm,
        feature_service: FeatureService | None = None
    ) -> None:
        super().__init__(settings=settings, daa=daa)
        self._feature_service = feature_service

    def verify_basic(self, block: Block, *, skip_block_weight_verification: bool = False) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if not skip_block_weight_verification:
            self.verify_weight(block)
        self.verify_reward(block)

    @cpu.profiler(key=lambda _, block: 'block-verify!{}'.format(block.hash.hex()))
    def verify(self, block: Block) -> None:
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight (done in HathorManager)
            (3) creates the correct amount of tokens in the output (done in HathorManager)
            (4) all parents must exist and have timestamp smaller than ours
            (5) data field must contain at most BLOCK_DATA_MAX_SIZE bytes
            (6) whether this block must signal feature support
        """
        # TODO Should we validate a limit of outputs?
        if block.is_genesis:
            # TODO do genesis validation
            return

        self.verify_without_storage(block)

        # (1) and (4)
        self.verify_parents(block)

        self.verify_height(block)

        self.verify_mandatory_signaling(block)

    def verify_without_storage(self, block: Block) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow(block)
        self.verify_no_inputs(block)
        self.verify_outputs(block)
        self.verify_data(block)
        self.verify_sigops_output(block)

    def verify_height(self, block: Block) -> None:
        """Validate that the block height is enough to confirm all transactions being confirmed."""
        meta = block.get_metadata()
        assert meta.height is not None
        assert meta.min_height is not None
        if meta.height < meta.min_height:
            raise RewardLocked(f'Block needs {meta.min_height} height but has {meta.height}')

    def verify_weight(self, block: Block) -> None:
        """Validate minimum block difficulty."""
        min_block_weight = self._daa.calculate_block_difficulty(block)
        if block.weight < min_block_weight - self._settings.WEIGHT_TOL:
            raise WeightError(f'Invalid new block {block.hash_hex}: weight ({block.weight}) is '
                              f'smaller than the minimum weight ({min_block_weight})')

    def verify_reward(self, block: Block) -> None:
        """Validate reward amount."""
        parent_block = block.get_block_parent()
        tokens_issued_per_block = self._daa.get_tokens_issued_per_block(parent_block.get_height() + 1)
        if block.sum_outputs != tokens_issued_per_block:
            raise InvalidBlockReward(
                f'Invalid number of issued tokens tag=invalid_issued_tokens tx.hash={block.hash_hex} '
                f'issued={block.sum_outputs} allowed={tokens_issued_per_block}'
            )

    def verify_no_inputs(self, block: Block) -> None:
        inputs = getattr(block, 'inputs', None)
        if inputs:
            raise BlockWithInputs('number of inputs {}'.format(len(inputs)))

    def verify_outputs(self, block: BaseTransaction) -> None:
        assert isinstance(block, Block)
        super().verify_outputs(block)
        for output in block.outputs:
            if output.get_token_index() > 0:
                raise BlockWithTokensError('in output: {}'.format(output.to_human_readable()))

    def verify_data(self, block: Block) -> None:
        if len(block.data) > self._settings.BLOCK_DATA_MAX_SIZE:
            raise TransactionDataError('block data has {} bytes'.format(len(block.data)))

    def verify_mandatory_signaling(self, block: Block) -> None:
        """Verify whether this block is missing mandatory signaling for any feature."""
        if not self._settings.FEATURE_ACTIVATION.enable_usage:
            return

        assert self._feature_service is not None

        signaling_state = self._feature_service.is_signaling_mandatory_features(block)

        match signaling_state:
            case BlockIsSignaling():
                return
            case BlockIsMissingSignal(feature):
                raise BlockMustSignalError(
                    f"Block must signal support for feature '{feature.value}' during MUST_SIGNAL phase."
                )
            case _:
                # TODO: This will be changed to assert_never() so mypy can check it.
                raise NotImplementedError
