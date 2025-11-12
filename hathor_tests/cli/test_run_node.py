from unittest.mock import ANY, patch

from hathor_cli.run_node import RunNode
from hathor_tests import unittest


class RunNodeTest(unittest.TestCase):
    # In this case we just want to go through the code to see if it's okay

    def test_temp_data(self):
        class CustomRunNode(RunNode):
            def start_manager(self) -> None:
                pass

            def register_signal_handlers(self) -> None:
                pass

        run_node = CustomRunNode(argv=['--temp-data'])
        self.assertTrue(run_node is not None)

    @patch('twisted.internet.reactor.listenTCP')
    def test_listen_tcp_ipv4(self, mock_listenTCP):
        """Should call listenTCP with no interface defined when using only IPv4"""
        class CustomRunNode(RunNode):
            def start_manager(self) -> None:
                pass

            def register_signal_handlers(self) -> None:
                pass

        run_node = CustomRunNode(argv=['--temp-data', '--status', '1234'])
        self.assertTrue(run_node is not None)

        mock_listenTCP.assert_called_with(1234, ANY)

    @patch('twisted.internet.reactor.listenTCP')
    def test_listen_tcp_ipv6(self, mock_listenTCP):
        """Should call listenTCP with interface='::0' when enabling IPv6"""
        class CustomRunNode(RunNode):
            def start_manager(self) -> None:
                pass

            def register_signal_handlers(self) -> None:
                pass

        run_node = CustomRunNode(argv=['--temp-data', '--x-enable-ipv6', '--status', '1234'])
        self.assertTrue(run_node is not None)

        mock_listenTCP.assert_called_with(1234, ANY, interface='::0')

    def test_validate_ipv4_or_ipv6(self):
        """The program should exit if no IP version is enabled"""
        class CustomRunNode(RunNode):
            def start_manager(self) -> None:
                pass

            def register_signal_handlers(self) -> None:
                pass

        # Should call system exit
        with self.assertRaises(SystemExit):
            CustomRunNode(argv=['--temp-data', '--x-disable-ipv4', '--status', '1234'])
