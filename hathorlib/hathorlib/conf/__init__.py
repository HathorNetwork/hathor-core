from pathlib import Path

from hathorlib.conf.get_settings import HathorSettings

parent_dir = Path(__file__).parent

MAINNET_SETTINGS_FILEPATH = str(parent_dir / 'mainnet.yml')
TESTNET_SETTINGS_FILEPATH = str(parent_dir / 'testnet.yml')

__all__ = [
    'MAINNET_SETTINGS_FILEPATH',
    'TESTNET_SETTINGS_FILEPATH',
    'HathorSettings',
]
