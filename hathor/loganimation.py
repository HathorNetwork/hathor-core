import os

from hathor.graphviz import GraphvizVisualizer
from hathor.manager import HathorManager
from hathor.pubsub import EventArguments, HathorEvents


class GraphvizLogAnimation:
    """ Create a Graphviz SVG after every arrival of new blocks and transactions.
    It was created for debugging purposes.

    In the future, it can be expanded to generate a video or a webpage to visualize the images.
    """
    def __init__(self, manager: HathorManager, dirname: str):
        self.manager: HathorManager = manager
        self.dirname: str = dirname
        self.sequence: int = 0
        self.is_running: bool = False
        self.format: str = 'png'

    def start(self) -> None:
        """ Start recording.
        """
        os.makedirs(self.dirname, exist_ok=True)
        self.manager.pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self.on_new_tx)
        self.is_running = True

    def stop(self):
        """ Stop recording.
        """
        self.manager.pubsub.unsubscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self.on_new_tx)
        self.is_running = False

    def on_new_tx(self, key: HathorEvents, args: EventArguments) -> None:
        """ This method is called every change in the DAG. It saves a new snapshot in disk.
        """
        if not self.is_running:
            return

        n = self.sequence

        tx_storage = self.manager.tx_storage

        graphviz = GraphvizVisualizer(tx_storage)
        graphviz.include_verifications = True
        graphviz.include_funds = True
        dot = graphviz.dot(format=self.format)
        dot.render(os.path.join(self.dirname, 'seq_{:010d}'.format(n)))

        self.sequence += 1
