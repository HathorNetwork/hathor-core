import os
import sys

from hathor.conf import UNITTESTS_SETTINGS_FILEPATH
from hathor.reactor import initialize_global_reactor

os.environ['HATHOR_CONFIG_YAML'] = os.environ.get('HATHOR_TEST_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)

if sys.platform == 'win32':
    # XXX: because rocksdb isn't available on Windows, we force using memory-storage for tests so most of them can run
    os.environ['HATHOR_TEST_MEMORY_STORAGE'] = 'true'

# TODO: We should remove this call from the module level.
initialize_global_reactor(use_asyncio_reactor=True)
