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

from typing import Optional

from pydantic import Extra

from hathor.feature_activation.feature import Feature
from hathor.utils.pydantic import BaseModel


class RunNodeArgs(BaseModel, extra=Extra.allow):
    """
    Class that represents the CLI arguments used by the run_node command.
    Arguments must also be added to hathor.cli.run_node.RunNode.create_parser.
    """
    hostname: Optional[str]
    auto_hostname: bool
    unsafe_mode: Optional[str]
    testnet: bool
    test_mode_tx_weight: bool
    dns: Optional[str]
    peer: Optional[str]
    sysctl: Optional[str]
    listen: list[str]
    bootstrap: Optional[list[str]]
    status: Optional[int]
    stratum: Optional[int]
    data: Optional[str]
    rocksdb_storage: bool
    memory_storage: bool
    memory_indexes: bool
    rocksdb_cache: Optional[int]
    wallet: Optional[str]
    wallet_enable_api: bool
    words: Optional[str]
    passphrase: bool
    unlock_wallet: bool
    wallet_index: bool
    utxo_index: bool
    prometheus: bool
    prometheus_prefix: str
    cache: bool
    cache_size: Optional[int]
    cache_interval: Optional[int]
    recursion_limit: Optional[int]
    allow_mining_without_peers: bool
    x_full_verification: bool
    procname_prefix: str
    allow_non_standard_script: bool
    max_output_script_size: Optional[int]
    sentry_dsn: Optional[str]
    enable_debug_api: bool
    enable_crash_api: bool
    x_enable_legacy_sync_v1_0: bool
    x_sync_bridge: bool
    x_sync_v2_only: bool
    x_localhost_only: bool
    x_rocksdb_indexes: bool
    x_enable_event_queue: bool
    peer_id_blacklist: list[str]
    config_yaml: Optional[str]
    signal_support: set[Feature]
    signal_not_support: set[Feature]
