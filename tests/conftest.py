import asyncio
import os

from twisted.internet import asyncioreactor

os.environ['HATHOR_CONFIG_FILE'] = 'hathor.conf.unittests'
asyncioreactor.install(asyncio.get_event_loop())
