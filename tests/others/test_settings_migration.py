#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.conf import MAINNET_SETTINGS_FILEPATH, TESTNET_SETTINGS_FILEPATH, UNITTESTS_SETTINGS_FILEPATH
from hathor.conf.mainnet import SETTINGS as MAINNET_SETTINGS
from hathor.conf.settings import HathorSettings
from hathor.conf.testnet import SETTINGS as TESTNET_SETTINGS
from hathor.conf.unittests import SETTINGS as UNITTESTS_SETTINGS

# TODO: These tests are temporary while settings via python coexist with settings via yaml, just to make sure
#  the conversion was made correctly. After python settings are removed, this file can be removed too.


def test_mainnet_settings_migration():
    assert MAINNET_SETTINGS == HathorSettings.from_yaml(filepath=MAINNET_SETTINGS_FILEPATH)


def test_testnet_settings_migration():
    assert TESTNET_SETTINGS == HathorSettings.from_yaml(filepath=TESTNET_SETTINGS_FILEPATH)


def test_unittests_settings_migration():
    assert UNITTESTS_SETTINGS == HathorSettings.from_yaml(filepath=UNITTESTS_SETTINGS_FILEPATH)
