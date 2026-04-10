from hathor.nanocontracts import Runner
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class TestTestRunner(BlueprintTestCase):
    def test_uses_composition(self) -> None:
        assert isinstance(self.runner._runner, Runner)
        assert not isinstance(self.runner, Runner)
        assert not hasattr(self.runner, 'get_blueprint_id')
        assert not hasattr(self.runner, 'block_storage')
