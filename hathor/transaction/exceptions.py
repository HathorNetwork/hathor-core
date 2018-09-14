from hathor.exception import HathorError


class DoubleSpend(HathorError):
    """Some input has already been spent"""


class InputOutputMismatch(HathorError):
    """Input and output amounts are not equal"""


class InvalidInputData(HathorError):
    """Input data does not solve output script correctly"""


class TooManyInputs(HathorError):
    """More than 256 inputs"""


class TooManyOutputs(HathorError):
    """More than 256 outputs"""


class PowError(HathorError):
    """Proof-of-work is not correct"""


class WeightError(HathorError):
    """Transaction not using correct weight"""


class BlockError(HathorError):
    """Base class for Block-specific errors"""


class BlockHeightError(BlockError):
    """Block not using correct height"""
