import pytest

from hathor.p2p.peer_storage import UnverifiedPeerStorage, VerifiedPeerStorage
from hathor.util import Random
from hathor_tests.unittest import PEER_ID_POOL


@pytest.fixture
def rng() -> Random:
    import secrets
    seed = secrets.randbits(64)
    return Random(seed)


def test_unverified_peer_storage_max_size(rng: Random) -> None:
    max_size = 5
    peer_storage = UnverifiedPeerStorage(rng=rng, max_size=max_size)
    for i in range(2 * max_size):
        peer = PEER_ID_POOL[i].to_unverified_peer()
        peer_storage.add(peer)
    assert len(peer_storage) == max_size


def test_verified_peer_storage_max_size(rng: Random) -> None:
    max_size = 5
    peer_storage = VerifiedPeerStorage(rng=rng, max_size=max_size)
    for i in range(2 * max_size):
        peer = PEER_ID_POOL[i].to_public_peer()
        peer_storage.add(peer)
    assert len(peer_storage) == max_size
