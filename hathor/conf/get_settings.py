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

from hathor.conf.settings import HathorSettings as Settings

_config_file: Optional[str] = None


def HathorSettings() -> Settings:
    """ Return configuration file namedtuple
        Get the file from environment variable 'HATHOR_CONFIG_FILE'
        If not set we return the config file of the mainnet
    """
    settings_module = get_settings_module()
    settings = getattr(settings_module, 'SETTINGS')
    assert isinstance(settings, Settings)
    return settings


def get_settings_module() -> ModuleType:
    global _config_file
    # Import config file for network
    default_file = 'hathor.conf.mainnet'
    config_file = os.environ.get('HATHOR_CONFIG_FILE', default_file)
    if _config_file is None:
        _config_file = config_file
    elif _config_file != config_file:
        raise Exception('loading config twice with a different file')
    try:
        module = importlib.import_module(config_file)
    except ModuleNotFoundError:
        module = importlib.import_module(default_file)
    return module
