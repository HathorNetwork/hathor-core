#  Copyright 2026 Hathor Labs
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

"""Required-checks table for the verification pipeline.

Encodes which VerificationCheck flags must be recorded for each (vertex type,
stage, conditional) combination. Must stay in sync with the dispatcher in
verification_service.py — drift is caught by test_required_checks_match_dispatcher.
"""

from enum import Enum

from hathor.conf.settings import HathorSettings
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.poa import PoaBlock
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.verification.verification_check import VerificationCheck as VC
from hathor.verification.verification_context import RequiredChecks
from hathor.verification.verification_params import VerificationParams


class Stage(Enum):
    VERIFY_BASIC = 'verify_basic'
    VERIFY = 'verify'
    POST_NANO_EXECUTION = 'post_nano_execution'


# Flags produced by verify_without_storage, by vertex kind.
# Note: verify_outputs internally calls verify_number_of_outputs, so
# NUMBER_OF_OUTPUTS is always recorded alongside OUTPUTS.

_BASE_BLOCK_WITHOUT_STORAGE = (
    VC.NO_INPUTS | VC.OUTPUTS | VC.NUMBER_OF_OUTPUTS | VC.BLOCK_OUTPUT_TOKEN_INDEXES
    | VC.BLOCK_DATA | VC.SIGOPS_OUTPUT
)


def _tx_without_storage_flags(*, is_pow: bool) -> VC:
    flags = (
        VC.NUMBER_OF_INPUTS | VC.OUTPUTS | VC.NUMBER_OF_OUTPUTS
        | VC.OUTPUT_TOKEN_INDEXES | VC.SIGOPS_OUTPUT | VC.TOKENS
    )
    if is_pow:
        flags |= VC.POW
    return flags


def _without_storage_for(vertex: BaseTransaction, *, is_pow: bool) -> VC:
    """Flags produced by verify_without_storage() for this vertex."""
    match vertex.version:
        case TxVersion.REGULAR_BLOCK | TxVersion.MERGE_MINED_BLOCK:
            flags = VC.POW | _BASE_BLOCK_WITHOUT_STORAGE
        case TxVersion.POA_BLOCK:
            flags = _BASE_BLOCK_WITHOUT_STORAGE  # no POW in PoA
        case TxVersion.REGULAR_TRANSACTION | TxVersion.TOKEN_CREATION_TRANSACTION:
            flags = _tx_without_storage_flags(is_pow=is_pow)
        case TxVersion.ON_CHAIN_BLUEPRINT:
            flags = (
                _tx_without_storage_flags(is_pow=is_pow)
                | VC.OCB_PUBKEY_ALLOWED | VC.OCB_NC_SIGNATURE | VC.OCB_CODE
            )
        case _:
            flags = VC(0)

    if vertex.has_fees():
        flags |= VC.FEE_LIST

    if vertex.is_nano_contract():
        flags |= VC.NANO_NC_SIGNATURE | VC.NANO_ACTIONS

    return flags


def _is_genesis_or_skipped(vertex: BaseTransaction, settings: HathorSettings) -> bool:
    if vertex.hash in settings.SKIP_VERIFICATION:
        return True
    if getattr(vertex, 'is_genesis', False):
        return True
    return False


def required_checks_for(
    vertex: BaseTransaction,
    params: VerificationParams,
    settings: HathorSettings,
    stage: Stage,
) -> RequiredChecks:
    """Return the flags that must be recorded in the VerificationContext after
    the given stage runs for the given vertex. Empty for genesis/skipped."""
    if _is_genesis_or_skipped(vertex, settings):
        return RequiredChecks()

    is_pow = settings.CONSENSUS_ALGORITHM.is_pow()

    if stage is Stage.VERIFY_BASIC:
        return _required_verify_basic(vertex, params, is_pow=is_pow)
    if stage is Stage.VERIFY:
        return _required_verify(vertex, params, is_pow=is_pow)
    if stage is Stage.POST_NANO_EXECUTION:
        return _required_post_nano(vertex)
    raise AssertionError(f'unknown stage {stage!r}')


def required_post_nano_checks(
    vertex: BaseTransaction,
    settings: HathorSettings,
) -> RequiredChecks:
    """Post-nano-execution required flags. Does not depend on VerificationParams,
    so it can be called from the block executor without threading params through."""
    if _is_genesis_or_skipped(vertex, settings):
        return RequiredChecks()
    return _required_post_nano(vertex)


def _required_verify_basic(
    vertex: BaseTransaction,
    params: VerificationParams,
    *,
    is_pow: bool,
) -> RequiredChecks:
    all_of = VC.VERSION_BASIC | VC.OLD_TIMESTAMP

    match vertex.version:
        case TxVersion.REGULAR_BLOCK | TxVersion.MERGE_MINED_BLOCK:
            all_of |= VC.REWARD | VC.CHECKPOINTS
            if not params.skip_block_weight_verification:
                all_of |= VC.BLOCK_WEIGHT
        case TxVersion.POA_BLOCK:
            all_of |= VC.POA | VC.REWARD
        case TxVersion.REGULAR_TRANSACTION | TxVersion.TOKEN_CREATION_TRANSACTION | TxVersion.ON_CHAIN_BLUEPRINT:
            # _verify_basic_tx: parents_basic + (weight if pow) + verify_without_storage.
            all_of |= VC.PARENTS_BASIC
            if is_pow:
                all_of |= VC.WEIGHT
            all_of |= _without_storage_for(vertex, is_pow=is_pow)

    return RequiredChecks(all_of=all_of)


def _required_verify(
    vertex: BaseTransaction,
    params: VerificationParams,
    *,
    is_pow: bool,
) -> RequiredChecks:
    """Incremental verify() stage requirements — only the flags that verify()
    itself records. verify_basic's flags are asserted separately by its own
    stage check, so verify() stays testable in isolation and the two stages
    remain orthogonal."""
    all_of = VC.HEADERS
    any_of_groups: tuple[VC, ...] = ()

    if isinstance(vertex, (Block, MergeMinedBlock, PoaBlock)):
        all_of |= _without_storage_for(vertex, is_pow=is_pow)
        all_of |= VC.PARENTS | VC.HEIGHT | VC.MANDATORY_SIGNALING
        if isinstance(vertex, MergeMinedBlock):
            all_of |= VC.AUX_POW
    elif isinstance(vertex, Transaction):
        # verify_without_storage re-runs inside _verify_tx for freshness, so its
        # flags are recorded again into the verify-stage ctx. Declare them here
        # so the dispatcher-completeness cross-check stays symmetric.
        all_of |= _without_storage_for(vertex, is_pow=is_pow)
        all_of |= VC.SIGOPS_INPUT | VC.INPUTS | VC.VERSION | VC.PARENTS | VC.CONFLICT
        if params.reject_locked_reward:
            all_of |= VC.REWARD_LOCKED
        # Balance: either BALANCE (fully verified) or BALANCE_POSTPONED (deferred
        # to nano execution) satisfies this stage. Post-nano we tighten to BALANCE.
        any_of_groups = any_of_groups + (VC.BALANCE | VC.BALANCE_POSTPONED,)
        if isinstance(vertex, TokenCreationTransaction):
            all_of |= VC.TOKEN_INFO | VC.MINTED_TOKENS
        if vertex.is_nano_contract():
            all_of |= VC.NANO_METHOD_CALL | VC.NANO_SEQNUM

    return RequiredChecks(all_of=all_of, any_of_groups=any_of_groups)


def _required_post_nano(vertex: BaseTransaction) -> RequiredChecks:
    """After nano-contract execution, the tx must have BALANCE recorded
    (not just BALANCE_POSTPONED). Applies to transactions only."""
    if not isinstance(vertex, Transaction):
        return RequiredChecks()
    return RequiredChecks(all_of=VC.BALANCE)
