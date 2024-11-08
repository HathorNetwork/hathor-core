from unittest.mock import ANY, Mock, patch

from hathor.cli.run_node import RunNode
from tests import unittest


class RunNodeTest(unittest.TestCase):
    # In this case we just want to go through the code to see if it's okay

    def test_memory_storage(self):
        class CustomRunNode(RunNode):
            def start_manager(self) -> None:
                pass

            def register_signal_handlers(self) -> None:
                pass

        run_node = CustomRunNode(argv=['--memory-storage'], logging_args=Mock())
        self.assertTrue(run_node is not None)

    @patch('twisted.internet.reactor.listenTCP')
    def test_listen_tcp_ipv4(self, mock_listenTCP):
        class CustomRunNode(RunNode):
            def start_manager(self) -> None:
                pass

            def register_signal_handlers(self) -> None:
                pass

        run_node = CustomRunNode(argv=['--memory-storage', '--status', '1234'], logging_args=Mock())
        self.assertTrue(run_node is not None)

        mock_listenTCP.assert_called_with(1234, ANY)
