import os
from typing import NamedTuple, Optional

from hathorlib.conf.settings import HathorSettings as Settings
from hathorlib.conf.utils import _load_module_settings, _load_yaml_settings

_config_file = None

class _SettingsMetadata(NamedTuple):
    source: str
    is_yaml: bool
    settings: Settings


_settings_singleton: Optional[_SettingsMetadata] = None


def HathorSettings() -> Settings:
    """ Return configuration file namedtuple
        Get the file from environment variable 'TXMINING_CONFIG_FILE'
        If not set we return the config file of the mainnet
    """
    settings_module_filepath = os.environ.get('HATHOR_CONFIG_FILE')
    if settings_module_filepath is not None:
        return _load_settings_singleton(settings_module_filepath, is_yaml=False)

    settings_yaml_filepath = os.environ.get('HATHOR_CONFIG_YAML', 'hathorlib.conf.mainnet')
    return _load_settings_singleton(settings_yaml_filepath, is_yaml=True)


def _load_settings_singleton(source: str, *, is_yaml: bool) -> Settings:
    global _settings_singleton

    if _settings_singleton is not None:
        if _settings_singleton.is_yaml != is_yaml:
            raise Exception('loading config twice with a different file type')
        if _settings_singleton.source != source:
            raise Exception('loading config twice with a different file')

        return _settings_singleton.settings

    settings_loader = _load_yaml_settings if is_yaml else _load_module_settings
    _settings_singleton = _SettingsMetadata(
        source=source,
        is_yaml=is_yaml,
        settings=settings_loader(Settings, source)
    )

    return _settings_singleton.settings
