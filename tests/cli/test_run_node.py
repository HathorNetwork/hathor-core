from argparse import Namespace

from hathor.cli.run_node import RunNode
from tests import unittest


class RunNodeTest(unittest.TestCase):
    # In this case we just want to go through the code to see if it's okay

    def test_memory_storage(self):
        class CustomRunNode(RunNode):
            def start_manager(self, args: Namespace) -> None:
                pass

            def register_signal_handlers(self, args: Namespace) -> None:
                pass

        run_node = CustomRunNode(argv=['--memory-storage'])
        self.assertTrue(run_node is not None)
