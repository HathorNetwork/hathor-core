# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathorlib.exceptions import (  # noqa: F401
    AuxPowError,
    AuxPowLongMerklePathError,
    AuxPowNoMagicError,
    AuxPowUnexpectedMagicError,
    BlockError,
    BlockHeightError,
    BlockMustSignalError,
    BlockWithInputs,
    BlockWithTokensError,
    CheckpointError,
    ConflictingInputs,
    ConflictWithConfirmedTxError,
    DataIndexError,
    DoubleSpend,
    DuplicatedParents,
    EqualVerifyFailed,
    FeeHeaderTokenNotFound,
    FinalStackInvalid,
    HathorError,
    HeaderNotSupported,
    IncorrectParents,
    InexistentInput,
    InputOutputMismatch,
    InputVoidedAndConfirmed,
    InvalidBlockReward,
    InvalidFeeAmount,
    InvalidFeeHeader,
    InvalidInputData,
    InvalidInputDataSize,
    InvalidOutputScriptSize,
    InvalidOutputValue,
    InvalidScriptError,
    InvalidStackData,
    InvalidToken,
    InvalidVersionError,
    MissingStackItems,
    OracleChecksigFailed,
    OutOfData,
    ParentDoesNotExist,
    PoaValidationError,
    PowError,
    RewardLocked,
    ScriptError,
    SerializedSizeError,
    TimeLocked,
    TimestampError,
    TokenNotFound,
    TooFewInputs,
    TooManyBetweenConflicts,
    TooManyHeaders,
    TooManyInputs,
    TooManyOutputs,
    TooManySigOps,
    TooManyTokens,
    TooManyWithinConflicts,
    TransactionDataError,
    TxValidationError,
    UnusedTokensError,
    VerifyFailed,
    WeightError,
)
from hathorlib.token_amount import UnsignedAmount


class ForbiddenMint(InputOutputMismatch):
    """Tokens were minted without authority inputs"""

    from hathor.types import TokenUid

    def __init__(self, amount: UnsignedAmount, token_uid: TokenUid) -> None:
        super().__init__(f'{amount} {token_uid.hex()} tokens minted, but there is no mint authority input')


class ForbiddenMelt(InputOutputMismatch):
    """Tokens were melted without authority inputs"""

    from hathor.types import TokenUid

    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    @classmethod
    def from_token(cls, amount: UnsignedAmount, token_uid: TokenUid) -> 'ForbiddenMelt':
        return cls(f'{amount} {token_uid.hex()} tokens melted, but there is no melt authority input')


class InvalidRangeProofError(TxValidationError):
    """Range proof is invalid."""


class InvalidSurjectionProofError(TxValidationError):
    """Surjection proof is invalid."""


class ShieldedBalanceMismatchError(TxValidationError):
    """Shielded balance equation does not hold."""


class TrivialCommitmentError(TxValidationError):
    """Rule 4: All transparent inputs require >= 2 shielded outputs."""


class ShieldedAuthorityError(TxValidationError):
    """Rule 7: Authority outputs cannot be shielded."""


class ShieldedMintMeltForbiddenError(TxValidationError):
    """Mint/melt operations are not allowed in transactions with shielded outputs."""


class InvalidShieldedOutputError(TxValidationError):
    """Generic invalid shielded output error."""


class InvalidMintMeltHeaderError(TxValidationError):
    """MintHeader or MeltHeader is malformed (bad entries, duplicates, out-of-range)."""
