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

from hathor import daa
from hathor.conf.settings import HathorSettings
from hathor.profiler import get_cpu_profiler
from hathor.transaction import Block
from hathor.transaction.exceptions import (
    BlockWithInputs,
    BlockWithTokensError,
    InvalidBlockReward,
    RewardLocked,
    TransactionDataError,
    WeightError,
)
from hathor.verification import vertex_verification

cpu = get_cpu_profiler()


def verify_basic(block: Block, *, settings: HathorSettings, skip_block_weight_verification: bool = False) -> None:
    """Partially run validations, the ones that need parents/inputs are skipped."""
    if not skip_block_weight_verification:
        verify_weight(block, settings=settings)
    verify_reward(block)


@cpu.profiler(key=lambda block: 'block-verify!{}'.format(block.hash.hex()))
def verify(block: Block, *, settings: HathorSettings) -> None:
    """
        (1) confirms at least two pending transactions and references last block
        (2) solves the pow with the correct weight (done in HathorManager)
        (3) creates the correct amount of tokens in the output (done in HathorManager)
        (4) all parents must exist and have timestamp smaller than ours
        (5) data field must contain at most BLOCK_DATA_MAX_SIZE bytes
    """
    # TODO Should we validate a limit of outputs?
    if block.is_genesis:
        # TODO do genesis validation
        return

    verify_without_storage(block, settings=settings)

    # (1) and (4)
    vertex_verification.verify_parents(block, settings=settings)

    verify_height(block)


def verify_weight(block: Block, *, settings: HathorSettings) -> None:
    """Validate minimum block difficulty."""
    block_weight = daa.calculate_block_difficulty(block)
    if block.weight < block_weight - settings.WEIGHT_TOL:
        raise WeightError(f'Invalid new block {block.hash_hex}: weight ({block.weight}) is '
                          f'smaller than the minimum weight ({block_weight})')


def verify_reward(block: Block) -> None:
    """Validate reward amount."""
    parent_block = block.get_block_parent()
    tokens_issued_per_block = daa.get_tokens_issued_per_block(parent_block.get_height() + 1)
    if block.sum_outputs != tokens_issued_per_block:
        raise InvalidBlockReward(
            f'Invalid number of issued tokens tag=invalid_issued_tokens tx.hash={block.hash_hex} '
            f'issued={block.sum_outputs} allowed={tokens_issued_per_block}'
        )


def verify_without_storage(block: Block, *, settings: HathorSettings) -> None:
    """ Run all verifications that do not need a storage.
    """
    vertex_verification.verify_pow(block)
    verify_no_inputs(block)
    verify_outputs(block, settings=settings)
    verify_data(block, settings=settings)
    vertex_verification.verify_sigops_output(block, settings=settings)


def verify_height(block: Block) -> None:
    """Validate that the block height is enough to confirm all transactions being confirmed."""
    meta = block.get_metadata()
    assert meta.height is not None
    assert meta.min_height is not None
    if meta.height < meta.min_height:
        raise RewardLocked(f'Block needs {meta.min_height} height but has {meta.height}')


def verify_no_inputs(block: Block) -> None:
    inputs = getattr(block, 'inputs', None)
    if inputs:
        raise BlockWithInputs('number of inputs {}'.format(len(inputs)))


def verify_outputs(block: Block, *, settings: HathorSettings) -> None:
    vertex_verification.verify_outputs(block, settings=settings)
    for output in block.outputs:
        if output.get_token_index() > 0:
            raise BlockWithTokensError('in output: {}'.format(output.to_human_readable()))


def verify_data(block: Block, *, settings: HathorSettings) -> None:
    if len(block.data) > settings.BLOCK_DATA_MAX_SIZE:
        raise TransactionDataError('block data has {} bytes'.format(len(block.data)))
