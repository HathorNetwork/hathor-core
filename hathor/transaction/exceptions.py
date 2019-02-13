from hathor.exception import HathorError


class TxValidationError(HathorError):
    """Base class for tx validation errors"""


class ParentDoesNotExist(TxValidationError):
    """A parent does not exist"""


class IncorrectParents(TxValidationError):
    """Wrong number of parents or confirming incorrect types of transactions:
    - block: 3 parents: 1 block, 2 transactions
    - tx: 2 parents, both transactions
    """


class TimestampError(TxValidationError):
    """Transaction timestamp is smaller or equal to one parent's timestamp"""


class DoubleSpend(TxValidationError):
    """Some input has already been spent"""


class InputOutputMismatch(TxValidationError):
    """Input and output amounts are not equal"""


class InvalidInputData(TxValidationError):
    """Input data does not solve output script correctly"""


class TooManyInputs(TxValidationError):
    """More than 256 inputs"""


class InexistentInput(TxValidationError):
    """Input tx does not exist or index spent does not exist"""


class ConflictingInputs(TxValidationError):
    """Inputs in the tx are spending the same output"""


class TooManyOutputs(TxValidationError):
    """More than 256 outputs"""


class PowError(TxValidationError):
    """Proof-of-work is not correct"""


class WeightError(TxValidationError):
    """Transaction not using correct weight"""


class DuplicatedParents(TxValidationError):
    """Transaction has duplicated parents"""


class InvalidToken(TxValidationError):
    """Token is not valid"""


class BlockError(TxValidationError):
    """Base class for Block-specific errors"""


class BlockWithInputs(BlockError):
    """Block has inputs"""


class BlockWithTokensError(BlockError):
    """Block has tokens other than hathor"""


class BlockDataError(BlockError):
    """Block data max length exceeded"""


class ScriptError(HathorError):
    """Base class for script evaluation errors"""


class OutOfData(ScriptError):
    """PUSHDATA operation with more bytes than we have available"""


class MissingStackItems(ScriptError):
    """Operation requires more items than what is on stack"""


class EqualVerifyFailed(ScriptError):
    """OP_EQUALVERIFY failed"""


class FinalStackInvalid(ScriptError):
    """Value left on stack is not true"""


class OracleChecksigFailed(ScriptError):
    """Signature, public key and data don't match. Used mostly with nano contracts"""


class DataIndexError(ScriptError):
    """The value for data at the given index does not exist.

    For example, if the data is of form 'value1:value2:value3' and we try to access value at index 5.
    """


class InvalidStackData(ScriptError):
    """The value for data on the stack is not what we expect

    For example, we expect an integer but it's not
    """


class VerifyFailed(ScriptError):
    """For all cases when there's a comparison that fails"""


class TimeLocked(ScriptError):
    """Transaction is invalid because it is time locked"""
