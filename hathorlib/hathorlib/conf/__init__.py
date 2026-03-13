from pathlib import Path

from hathorlib.conf.get_settings import HathorSettings

parent_dir = Path(__file__).parent

MAINNET_SETTINGS_FILEPATH = str(parent_dir / 'mainnet.yml')
TESTNET_INDIA_SETTINGS_FILEPATH = str(parent_dir / 'testnet.yml')
NANO_TESTNET_SETTINGS_FILEPATH = str(parent_dir / 'nano_testnet.yml')
LOCALNET_SETTINGS_FILEPATH = str(parent_dir / 'localnet.yml')
UNITTESTS_SETTINGS_FILEPATH = str(parent_dir / 'unittests.yml')

__all__ = [
    'MAINNET_SETTINGS_FILEPATH',
    'TESTNET_INDIA_SETTINGS_FILEPATH',
    'NANO_TESTNET_SETTINGS_FILEPATH',
    'LOCALNET_SETTINGS_FILEPATH',
    'UNITTESTS_SETTINGS_FILEPATH',
    'HathorSettings',
]
