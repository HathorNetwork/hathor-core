import unittest
from hathor.p2p.peer_id import PeerId, InvalidPeerIdException


class PeerIdTest(unittest.TestCase):
    def test_invalid_id(self):
        p1 = PeerId()
        p1.id = p1.id[::-1]
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_invalid_public_key(self):
        p1 = PeerId()
        p2 = PeerId()
        p1.public_key = p2.public_key
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_invalid_private_key(self):
        p1 = PeerId()
        p2 = PeerId()
        p1.private_key = p2.private_key
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_no_private_key(self):
        p1 = PeerId()
        p1.private_key = None
        p1.validate()

    def test_create_from_json(self):
        p1 = PeerId()
        data1 = p1.to_json(include_private_key=True)
        p2 = PeerId.create_from_json(data1)
        data2 = p2.to_json(include_private_key=True)
        self.assertEqual(data1, data2)
        p2.validate()

    def test_create_from_json_without_private_key(self):
        p1 = PeerId()
        data1 = p1.to_json()
        p2 = PeerId.create_from_json(data1)
        data2 = p2.to_json()
        self.assertEqual(data1, data2)
        p2.validate()

    def test_sign_verify(self):
        data = b'abacate'
        p1 = PeerId()
        signature = p1.sign(data)
        self.assertTrue(p1.verify_signature(signature, data))

    def test_sign_verify_fail(self):
        data = b'abacate'
        p1 = PeerId()
        signature = p1.sign(data)
        signature = signature[::-1]
        self.assertFalse(p1.verify_signature(signature, data))


if __name__ == '__main__':
    unittest.main()
