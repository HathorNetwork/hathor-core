import asyncio
import os
import sys

from twisted.internet import asyncioreactor

from hathor.conf import UNITTESTS_SETTINGS_FILEPATH

os.environ['HATHOR_CONFIG_YAML'] = os.environ.get('HATHOR_TEST_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)

if sys.platform == 'win32':
    # See: https://twistedmatrix.com/documents/current/api/twisted.internet.asyncioreactor.AsyncioSelectorReactor.html
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # XXX: because rocksdb isn't available on Windows, we force using memory-storage for tests so most of them can run
    os.environ['HATHOR_TEST_MEMORY_STORAGE'] = 'true'

asyncioreactor.install(asyncio.get_event_loop())
