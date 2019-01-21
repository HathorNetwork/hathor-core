import os

from hathor.manager import HathorEvents, HathorManager


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

    def on_new_tx(self) -> None:
        """ This method is called every change in the DAG. It saves a new snapshot in disk.
        """
        if not self.is_running:
            return

        n = self.sequence

        dot1 = self.manager.tx_storage.graphviz(format=self.format)
        dot1.render(os.path.join(self.dirname, 'seq_v_{:010d}'.format(n)))

        dot2 = self.manager.tx_storage.graphviz_funds(format='png')
        dot2.render(os.path.join(self.dirname, 'seq_f_{:010d}'.format(n)))

        self.sequence += 1
