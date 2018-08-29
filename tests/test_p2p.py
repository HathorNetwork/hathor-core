import unittest
from hathor.p2p.peer_id import PeerId


class PeerIdTest(unittest.TestCase):
    def test_create_from_json(self):
        p1 = PeerId()
        data = p1.to_json(include_private_keys=True)
        p2 = PeerId.create_from_json(data)
        self.assertEqual(p1.id, p2.id)
        self.assertEqual(p1.private_key, p2.private_key)
        self.assertEqual(p1.public_key, p2.public_key)


if __name__ == '__main__':
    unittest.main()
