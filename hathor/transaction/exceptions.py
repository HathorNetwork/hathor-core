# Copyright 2021 Hathor Labs
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


class ForbiddenMint(InputOutputMismatch):
    """Tokens were minted without authority inputs"""

    from hathor.types import TokenUid

    def __init__(self, amount: int, token_uid: TokenUid) -> None:
        super().__init__('{} {} tokens minted, but there is no mint authority input'.format(
            (-1) * amount, token_uid.hex()))


class ForbiddenMelt(InputOutputMismatch):
    """Tokens were melted without authority inputs"""

    from hathor.types import TokenUid

    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    @classmethod
    def from_token(cls, amount: int, token_uid: TokenUid) -> 'ForbiddenMelt':
        return cls('{} {} tokens melted, but there is no melt authority input'.format(
            (-1) * amount, token_uid.hex()))
