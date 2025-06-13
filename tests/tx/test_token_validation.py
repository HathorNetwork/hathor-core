
import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.transaction.exceptions import TransactionDataError
from hathor.transaction.util import validate_token_name_and_symbol


def test_token_name():
    settings = get_global_settings()

    validate_token_name_and_symbol(settings, 'TOKEN', 'TKN')
    validate_token_name_and_symbol(settings, 'TOKEN', 'X')
    validate_token_name_and_symbol(settings, 'TOKEN', 'XY')
    validate_token_name_and_symbol(settings, 'TOKEN', 'XYZ')
    validate_token_name_and_symbol(settings, 'TOKEN', 'XYZW')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, '', 'X')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, 'TOKEN', '')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, 'HATHOR', 'X')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, ' HATHOR', 'X')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, ' HATHOR ', 'X')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, 'HATHOR ', 'X')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, 'TOKEN', 'HTR')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, 'TOKEN', ' HTR')

    with pytest.raises(TransactionDataError):
        validate_token_name_and_symbol(settings, 'TOKEN', 'HTR ')
