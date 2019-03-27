import importlib
import os

from hathor.conf.settings import HathorSettings as Settings


def HathorSettings() -> Settings:
    """ Return configuration file namedtuple
        Get the file from environment variable 'HATHOR_CONFIG_FILE'
        If not set we return the config file of the mainnet
    """
    # Import config file for network
    default_file = 'hathor.conf.mainnet'
    config_file = os.environ.get('HATHOR_CONFIG_FILE', default_file)
    try:
        module = importlib.import_module(config_file)
    except ModuleNotFoundError:
        module = importlib.import_module(default_file)
    return module.SETTINGS  # type: ignore
