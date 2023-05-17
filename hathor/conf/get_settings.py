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

import importlib
import os
from types import ModuleType
from typing import Optional

from structlog import get_logger

from hathor import conf
from hathor.conf.settings import HathorSettings as Settings

logger = get_logger()

_settings_filepath: Optional[str] = None
_config_file: Optional[str] = None


def HathorSettings() -> Settings:
    """
    Returns the configuration named tuple.

    Tries to get the configuration from a python module in the 'HATHOR_CONFIG_FILE' env var, which will be deprecated.
    If not found, tries to get it from a yaml filepath in the 'HATHOR_YAML_CONFIG', which will be the new standard.

    If neither is set, or if the module import fails, the mainnet configuration is returned.
    """
    settings_module = get_settings_module()

    if settings_module is not None:
        log = logger.new()
        log.warn(
            "Setting a config module via the 'HATHOR_CONFIG_FILE' env var will be deprecated soon. "
            "Use the '--config-yaml' CLI option or the 'HATHOR_CONFIG_YAML' env var to set a yaml filepath instead."
        )
        settings = getattr(settings_module, 'SETTINGS')
        assert isinstance(settings, Settings)
        return settings

    settings_filepath = get_settings_filepath()

    return Settings.from_yaml(filepath=settings_filepath)


def get_settings_module() -> Optional[ModuleType]:
    global _config_file
    # Import config file for network
    config_file = os.environ.get('HATHOR_CONFIG_FILE')
    if _config_file is None:
        _config_file = config_file
    elif _config_file != config_file:
        raise Exception('loading config twice with a different file')

    if not config_file:
        return None

    try:
        module = importlib.import_module(config_file)
    except ModuleNotFoundError:
        default_file = 'hathor.conf.mainnet'
        module = importlib.import_module(default_file)

    return module


def get_settings_filepath() -> str:
    global _settings_filepath

    new_settings_filepath = os.environ.get('HATHOR_CONFIG_YAML', conf.MAINNET_SETTINGS_FILEPATH)

    if _settings_filepath is not None and _settings_filepath != new_settings_filepath:
        raise Exception('loading config twice with a different file')

    _settings_filepath = new_settings_filepath

    return new_settings_filepath
