import importlib
import os

from hathorlib.conf.settings import HathorSettings as Settings

_config_file = None


def HathorSettings() -> Settings:
    """ Return configuration file namedtuple
        Get the file from environment variable 'TXMINING_CONFIG_FILE'
        If not set we return the config file of the mainnet
    """
    global _config_file
    # Import config file for network
    default_file = 'hathorlib.conf.mainnet'
    config_file = os.environ.get('TXMINING_CONFIG_FILE', default_file)
    if _config_file is None:
        _config_file = config_file
    elif _config_file != config_file:
        raise Exception('loading config twice with a different file')
    try:
        module = importlib.import_module(config_file)
    except ModuleNotFoundError:
        module = importlib.import_module(default_file)
    return module.SETTINGS  # type: ignore
