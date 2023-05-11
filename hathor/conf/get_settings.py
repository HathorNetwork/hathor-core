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

import os
from typing import Optional

import yaml

from hathor import conf
from hathor.conf.settings import HathorSettings as Settings

_settings_filepath: Optional[str] = None


def HathorSettings() -> Settings:
    settings_filepath = get_settings_filepath()

    with open(settings_filepath, 'r') as file:
        settings_dict = yaml.safe_load(file)

        return Settings(**settings_dict)


def get_settings_filepath() -> str:
    global _settings_filepath

    new_settings_filepath = os.environ.get('HATHOR_CONFIG_FILE', conf.MAINNET_SETTINGS_FILEPATH)

    if _settings_filepath is not None and _settings_filepath != new_settings_filepath:
        raise Exception('loading config twice with a different file')

    _settings_filepath = new_settings_filepath

    return new_settings_filepath
