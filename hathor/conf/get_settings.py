# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import os
from typing import TYPE_CHECKING, NamedTuple, Optional

from structlog import get_logger

from hathorlib.conf.utils import _load_module_settings, _load_yaml_settings

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings as Settings

logger = get_logger()


class _SettingsMetadata(NamedTuple):
    source: str
    is_yaml: bool
    settings: Settings


_settings_singleton: Optional[_SettingsMetadata] = None


def get_global_settings() -> Settings:
    return HathorSettings()


def HathorSettings() -> Settings:
    """
    Returns the configuration named tuple.

    Tries to get the configuration from a python module in the 'HATHOR_CONFIG_FILE' env var, which will be deprecated.
    If not found, tries to get it from a yaml filepath in the 'HATHOR_YAML_CONFIG', which will be the new standard.

    If neither is set, or if the module import fails, the mainnet configuration is returned.
    """

    settings_module_filepath = os.environ.get('HATHOR_CONFIG_FILE')
    if settings_module_filepath is not None:
        return _load_settings_singleton(settings_module_filepath, is_yaml=False)

    from hathor import conf
    settings_yaml_filepath = os.environ.get('HATHOR_CONFIG_YAML', conf.MAINNET_SETTINGS_FILEPATH)
    return _load_settings_singleton(settings_yaml_filepath, is_yaml=True)


def get_settings_source() -> str:
    """ Returns the path of the settings module or YAML file that was loaded.

    XXX: Will raise an assertion error if HathorSettings() wasn't used before.
    """
    global _settings_singleton
    assert _settings_singleton is not None, 'HathorSettings() not called before'
    return _settings_singleton.source


def _load_settings_singleton(source: str, *, is_yaml: bool) -> Settings:
    global _settings_singleton

    if _settings_singleton is not None:
        if _settings_singleton.is_yaml != is_yaml:
            raise Exception('loading config twice with a different file type')
        if _settings_singleton.source != source:
            raise Exception('loading config twice with a different file')

        return _settings_singleton.settings

    if not is_yaml:
        log = logger.new()
        log.warn(
            "Setting a config module via the 'HATHOR_CONFIG_FILE' env var will be deprecated soon. "
            "Use the '--config-yaml' CLI option or the 'HATHOR_CONFIG_YAML' env var to set a yaml filepath instead."
        )
    settings_loader = _load_yaml_settings if is_yaml else _load_module_settings
    _settings_singleton = _SettingsMetadata(
        source=source,
        is_yaml=is_yaml,
        settings=settings_loader(Settings, source)
    )

    return _settings_singleton.settings
