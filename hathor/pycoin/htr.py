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

from pycoin.networks.bitcoinish import create_bitcoinish_network

from hathor.conf import HathorSettings

settings = HathorSettings()

network = create_bitcoinish_network(
    symbol='HTR', network_name='Hathor', subnet_name='mainnet',
    wif_prefix_hex='80',
    address_prefix_hex=settings.P2PKH_VERSION_BYTE.hex(),
    pay_to_script_prefix_hex=settings.MULTISIG_VERSION_BYTE.hex(),
    bip32_prv_prefix_hex='0488ade4', bip32_pub_prefix_hex='0488B21E',
)
