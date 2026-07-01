import os

from hathor.reactor import initialize_global_reactor
from hathor_tests.token_amount import UnsignedAmount
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH

os.environ['HATHOR_CONFIG_YAML'] = os.environ.get('HATHOR_TEST_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)

# TODO: We should remove this call from the module level.
initialize_global_reactor(use_asyncio_reactor=True)

# Hardcoded for all tests.
UnsignedAmount.set_decimal_places(v1_decimal_places=2, v2_decimal_places=18)
