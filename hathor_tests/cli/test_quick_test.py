from hathor_cli.quick_test import QuickTest
from hathor_tests import unittest


class TestQuickTest(unittest.TestCase):
    def test_quick_test(self):
        class CustomQuickTest(QuickTest):
            def start_manager(self) -> None:
                pass

            def register_signal_handlers(self) -> None:
                pass

        quick_test = CustomQuickTest(argv=['--temp-data', '--no-wait'])
        assert quick_test is not None

        self.clean_pending(required_to_quiesce=False)
