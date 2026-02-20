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

from pydantic import ConfigDict

from hathor.feature_activation.feature import Feature  # skip-cli-import-custom-check
from hathor.nanocontracts.nc_exec_logs import NCLogConfig  # skip-cli-import-custom-check
from hathor.utils.pydantic import BaseModel  # skip-cli-import-custom-check


class RunNodeArgs(BaseModel):
    """
    Class that represents the CLI arguments used by the run_node command.
    Arguments must also be added to hathor_cli.run_node.RunNode.create_parser.
    """
    model_config = ConfigDict(extra='allow')

    hostname: Optional[str]
    auto_hostname: bool
    unsafe_mode: Optional[str]
    testnet: bool
    testnet_hotel: bool
    testnet_golf: bool
    test_mode_tx_weight: bool
    dns: Optional[str]
    peer: Optional[str]
    sysctl: Optional[str]
    listen: list[str]
    bootstrap: Optional[list[str]]
    status: Optional[int]
    x_status_ipv6_interface: Optional[str]
    stratum: Optional[int]
    x_stratum_ipv6_interface: Optional[str]
    data: Optional[str]
    memory_storage: bool
    memory_indexes: bool
    temp_data: bool
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
    disable_cache: bool
    cache_size: Optional[int]
    cache_interval: Optional[int]
    recursion_limit: Optional[int]
    allow_mining_without_peers: bool
    procname_prefix: str
    allow_non_standard_script: bool
    max_output_script_size: Optional[int]
    sentry_dsn: Optional[str]
    enable_debug_api: bool
    enable_crash_api: bool
    x_sync_bridge: bool
    x_sync_v1_only: bool
    x_sync_v2_only: bool
    x_remove_sync_v1: bool
    sync_bridge: bool
    sync_v1_only: bool
    sync_v2_only: bool
    x_localhost_only: bool
    x_enable_event_queue: bool
    enable_event_queue: bool
    peer_id_blacklist: list[str]
    config_yaml: Optional[str]
    signal_support: set[Feature]
    signal_not_support: set[Feature]
    x_asyncio_reactor: bool
    x_ipython_kernel: bool
    nano_testnet: bool
    log_vertex_bytes: bool
    disable_ws_history_streaming: bool
    x_enable_ipv6: bool
    x_disable_ipv4: bool
    localnet: bool
    x_p2p_whitelist: Optional[str]
    nc_indexes: bool
    nc_exec_logs: NCLogConfig
    nc_exec_fail_trace: bool
