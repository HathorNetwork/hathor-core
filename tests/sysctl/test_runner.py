
import pytest

from hathor.sysctl import Sysctl
from hathor.sysctl.runner import SysctlRunner


@pytest.mark.parametrize(
    'args',
    [
        'string',
        "\"",
        1,
        True,
        False,
        'a,b',
        (1, 2, 3),
        (1, 'string', True),
        [1, 2, 3],
        (1, [1, 2, 3]),
        (1, ["a,a,a", "b", "c"]),
    ]
)
def test_deserialize(args):
    root = Sysctl()
    runner = SysctlRunner(root)

    args_serialized = runner.serialize(args)
    args_deserialized = runner.deserialize(args_serialized)

    assert args == args_deserialized
