from hathor.exception import HathorError


class DoubleSpend(HathorError):
    """Some input has already been spent"""


class InputOutputMismatch(HathorError):
    """Input and output amounts are not equal"""


class TooManyInputs(HathorError):
    """More than 256 inputs"""


class TooManyOutputs(HathorError):
    """More than 256 outputs"""


class PowError(HathorError):
    """Proof-of-work is not correct """


class WeightError(HathorError):
    """Transaction not using correct weight"""


class InputSignatureError(HathorError):
    """Incorrect input signature"""


class InputPublicKeyError(HathorError):
    """Public key does not match address"""
