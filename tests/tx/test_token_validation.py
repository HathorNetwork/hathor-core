
import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.transaction.exceptions import TransactionDataError
from hathor.transaction.token_info import TokenInfoVersion
from hathor.transaction.util import validate_token_info


def test_token_name():
    settings = get_global_settings()

    validate_token_info(settings, 'TOKEN', 'TKN', TokenInfoVersion.DEPOSIT)
    validate_token_info(settings, 'TOKEN', 'X', TokenInfoVersion.DEPOSIT)
    validate_token_info(settings, 'TOKEN', 'XY', TokenInfoVersion.DEPOSIT)
    validate_token_info(settings, 'TOKEN', 'XYZ', TokenInfoVersion.FEE)
    validate_token_info(settings, 'TOKEN', 'XYZW', TokenInfoVersion.FEE)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, '', 'X', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TOKEN', '', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'HATHOR', 'X', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, ' HATHOR', 'X', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, ' HATHOR ', 'X', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'HATHOR ', 'X', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TOKEN', 'HTR', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TOKEN', ' HTR', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TOKEN', 'HTR ', TokenInfoVersion.DEPOSIT)

    with pytest.raises(TransactionDataError):
        validate_token_info(settings, 'TRP', 'ASD ', None)
