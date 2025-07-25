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

from pathlib import Path

from hathor.conf.get_settings import HathorSettings

parent_dir = Path(__file__).parent

MAINNET_SETTINGS_FILEPATH = str(parent_dir / 'mainnet.yml')
TESTNET_SETTINGS_FILEPATH = str(parent_dir / 'testnet.yml')
TESTNET_HOTEL_SETTINGS_FILEPATH = str(parent_dir / 'testnet_hotel.yml')
NANO_TESTNET_SETTINGS_FILEPATH = str(parent_dir / 'nano_testnet.yml')
LOCALNET_SETTINGS_FILEPATH = str(parent_dir / 'localnet.yml')
UNITTESTS_SETTINGS_FILEPATH = str(parent_dir / 'unittests.yml')

__all__ = [
    'MAINNET_SETTINGS_FILEPATH',
    'TESTNET_SETTINGS_FILEPATH',
    'TESTNET_HOTEL_SETTINGS_FILEPATH',
    'NANO_TESTNET_SETTINGS_FILEPATH',
    'LOCALNET_SETTINGS_FILEPATH',
    'UNITTESTS_SETTINGS_FILEPATH',
    'HathorSettings',
]
