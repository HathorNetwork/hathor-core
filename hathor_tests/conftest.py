import os

from hathor.conf import UNITTESTS_SETTINGS_FILEPATH
from hathor.reactor import initialize_global_reactor

os.environ['HATHOR_CONFIG_YAML'] = os.environ.get('HATHOR_TEST_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)

# TODO: We should remove this call from the module level.
initialize_global_reactor(use_asyncio_reactor=True)
