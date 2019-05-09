import os

from prometheus_client import CollectorRegistry, Gauge, write_to_textfile
from twisted.internet import reactor

# Define prometheus metrics and it's explanation
METRIC_INFO = {
    'transactions': 'Number of transactions',
    'blocks': 'Number of blocks',
    'hash_rate': 'Hash rate of blocks with old calculus',
    'peers': 'Peers connected in the network',
    'block_hash_rate': 'Hash rate of blocks',
    'tx_hash_rate': 'Hash rate of tx',
    'best_block_weight': 'Weight of blocks',
    'websocket_connections': 'Number of connections in the websocket',
    'subscribed_addresses': 'Number of subscribed addresses in the websocket',
}


class PrometheusMetricsExporter:
    """ Class that sends hathor metrics to a node exporter that will be read by Prometheus
    """

    def __init__(self, metrics, path, filename='hathor.prom'):
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
        self.filepath = os.path.join(path, filename)

        # Stores all Gauge objects for each metric (key is the metric name)
        # Dict[str, prometheus_client.Gauge]
        self.metric_gauges = {}

        # Setup initial prometheus lib objects for each metric
        self._initial_setup()

        # Interval in which the write data method will be called (in seconds)
        self.call_interval = 5

        # If exporter is running
        self.running = False

    def _initial_setup(self):
        """ Start a collector registry to send data to node exporter
            and create one object to hold each metric data
        """
        self.registry = CollectorRegistry()

        for name, comment in METRIC_INFO.items():
            self.metric_gauges[name] = Gauge(name, comment, registry=self.registry)

    def start(self):
        """ Starts exporter
        """
        self.running = True
        self._schedule_and_write_data()

    def set_new_metrics(self):
        """ Update metric_gauges dict with new data from metrics
        """
        for metric_name in METRIC_INFO.keys():
            self.metric_gauges[metric_name].set(getattr(self.metrics, metric_name))

        write_to_textfile(self.filepath, self.registry)

    def _schedule_and_write_data(self):
        """ Update all metric data with new values
            Write new data to file
            Schedule next call
        """
        if self.running:
            self.set_new_metrics()

            # Schedule next call
            reactor.callLater(self.call_interval, self._schedule_and_write_data)

    def stop(self):
        """ Stops exporter
        """
        self.running = False
