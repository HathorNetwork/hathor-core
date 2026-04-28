import os

from hathor.reactor import initialize_global_reactor
from hathor_cli.util import LoggingOptions, LoggingOutput, setup_logging
from hathorlib.conf import UNITTESTS_SETTINGS_FILEPATH

os.environ['HATHOR_CONFIG_YAML'] = os.environ.get('HATHOR_TEST_CONFIG_YAML', UNITTESTS_SETTINGS_FILEPATH)


setup_logging(
    logging_output=LoggingOutput.PRETTY,
    logging_options=LoggingOptions(debug=True, sentry=False),
)

# TODO: We should remove this call from the module level.
initialize_global_reactor(use_asyncio_reactor=True)
