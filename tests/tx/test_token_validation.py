
import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.transaction.exceptions import TransactionDataError
from hathor.transaction.token_info import TokenVersion
from hathor.transaction.util import validate_token_info


def test_token_name():
    settings = get_global_settings()

    validate_token_info(settings, 'TOKEN', 'TKN', TokenVersion.DEPOSIT)
    validate_token_info(settings, 'TOKEN', 'X', TokenVersion.DEPOSIT)
    validate_token_info(settings, 'TOKEN', 'XY', TokenVersion.DEPOSIT)
    validate_token_info(settings, 'TOKEN', 'XYZ', TokenVersion.FEE)
    validate_token_info(settings, 'TOKEN', 'XYZW', TokenVersion.FEE)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, '', 'X', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TOKEN', '', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'HATHOR', 'X', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, ' HATHOR', 'X', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, ' HATHOR ', 'X', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'HATHOR ', 'X', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TOKEN', 'HTR', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TOKEN', ' HTR', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TOKEN', 'HTR ', TokenVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TRP', 'ASD ', TokenVersion.NATIVE)
