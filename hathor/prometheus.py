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
from typing import TYPE_CHECKING, Dict

from prometheus_client import CollectorRegistry, Gauge, write_to_textfile
from twisted.internet.task import LoopingCall

from hathor.conf import HathorSettings
from hathor.util import reactor

if TYPE_CHECKING:
    from hathor.metrics import Metrics

settings = HathorSettings()

METRIC_PREFIX = 'hathor_core:'

# Define prometheus metrics and it's explanation
METRIC_INFO = {
    'transactions': 'Number of transactions',
    'blocks': 'Number of blocks',
    'hash_rate': 'Hash rate of blocks with old calculus',
    'peers': 'Peers connected in the network',
    'best_block_weight': 'Weight of blocks',
    'best_block_height': 'Height of best chain',
    'websocket_connections': 'Number of connections in the websocket',
    'subscribed_addresses': 'Number of subscribed addresses in the websocket',
    'completed_jobs': 'Number of completed jobs in stratum',
    'blocks_found': 'Number of blocks found by the miner in stratum',
    'estimated_hash_rate': 'Estimated hash rate for stratum miners',
    'send_token_timeouts': 'Number of times send_token API has timed-out',
}

# Defines the metrics related to peer connections
PEER_CONNECTION_METRICS = {
    "received_messages": Gauge(
        METRIC_PREFIX + "peer_connection_received_messages",
        "Counts how many messages the node received from a peer",
        labelnames=["network", "connection_string", "peer_id"],
    ),
    "sent_messages": Gauge(
        METRIC_PREFIX + "peer_connection_sent_messages",
        "Counts how many messages the node sent to a peer",
        labelnames=["network", "connection_string", "peer_id"],
    ),
    "received_bytes": Gauge(
        METRIC_PREFIX + "peer_connection_received_bytes",
        "Counts how many bytes the node received from a peer",
        labelnames=["network", "connection_string", "peer_id"],
    ),
    "sent_bytes": Gauge(
        METRIC_PREFIX + "peer_connection_sent_bytes",
        "Counts how many bytes the node sent to a peer",
        labelnames=["network", "connection_string", "peer_id"],
    ),
    "received_txs": Gauge(
        METRIC_PREFIX + "peer_connection_received_txs",
        "Counts how many txs the node received from a peer",
        labelnames=["network", "connection_string", "peer_id"],
    ),
    "discarded_txs": Gauge(
        METRIC_PREFIX + "peer_connection_discarded_txs",
        "Counts how many txs the node discarded from a peer",
        labelnames=["network", "connection_string", "peer_id"],
    ),
    "received_blocks": Gauge(
        METRIC_PREFIX + "peer_connection_received_blocks",
        "Counts how many blocks the node received from a peer",
        labelnames=["network", "connection_string", "peer_id"],
    ),
    "discarded_blocks": Gauge(
        METRIC_PREFIX + "peer_connection_discarded_blocks",
        "Counts how many blocks the node discarded from a peer",
        labelnames=["network", "connection_string", "peer_id"],
    ),
}


class PrometheusMetricsExporter:
    """ Class that sends hathor metrics to a node exporter that will be read by Prometheus
    """

    def __init__(self, metrics: 'Metrics', path: str, filename: str = 'hathor.prom'):
        """
        :param metrics: Metric object that stores all the hathor metrics
        :type metrics: :py:class:`hathor.metrics.Metrics`

        :param path: Path to save the prometheus file
        :type path: str

        :param filename: Name of the prometheus file (must end in .prom)
        :type filename: str
        """
        self.metrics = metrics

        # Create full directory, if does not exist
        os.makedirs(path, exist_ok=True)

        # Full filepath with filename
        self.filepath: str = os.path.join(path, filename)

        # Stores all Gauge objects for each metric (key is the metric name)
        # Dict[str, prometheus_client.Gauge]
        self.metric_gauges: Dict[str, Gauge] = {}

        # Setup initial prometheus lib objects for each metric
        self._initial_setup()

        # If exporter is running
        self.running: bool = False

        # Interval in which the write data method will be called (in seconds)
        self.call_interval: int = settings.PROMETHEUS_WRITE_INTERVAL

        # A timer to periodically write data to prometheus
        self._lc_write_data = LoopingCall(self._write_data)
        self._lc_write_data.clock = reactor

    def _initial_setup(self) -> None:
        """ Start a collector registry to send data to node exporter
            and create one object to hold each metric data
        """
        self.registry = CollectorRegistry()

        for name, comment in METRIC_INFO.items():
            self.metric_gauges[name] = Gauge(name, comment, registry=self.registry)

        for _, metric in PEER_CONNECTION_METRICS.items():
            self.registry.register(metric)

    def start(self) -> None:
        """ Starts exporter
        """
        self.running = True
        self._lc_write_data.start(self.call_interval, now=False)

    def set_new_metrics(self) -> None:
        """ Update metric_gauges dict with new data from metrics
        """
        for metric_name in METRIC_INFO.keys():
            self.metric_gauges[metric_name].set(getattr(self.metrics, metric_name))

        for metric in PEER_CONNECTION_METRICS.keys():
            for connection_metric in self.metrics.peer_connection_metrics:
                PEER_CONNECTION_METRICS[metric].labels(
                    network=connection_metric.network,
                    peer_id=connection_metric.peer_id,
                    connection_string=connection_metric.connection_string
                ).set(getattr(connection_metric, metric))

        write_to_textfile(self.filepath, self.registry)

    def _write_data(self) -> None:
        """ Update all metric data with new values
            Write new data to file
        """
        self.set_new_metrics()

    def stop(self) -> None:
        """ Stops exporter
        """
        self.running = False
        if self._lc_write_data.running:
            self._lc_write_data.stop()
