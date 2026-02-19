from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.utils import (
    add_blacklist_peers,
    add_peer_id_blacklist,
    list_blacklist_peers,
    remove_blacklist_peers,
)
from hathor_tests import unittest


class NetfilterUtilsTest(unittest.TestCase):
    def setUp(self) -> None:
        """Clean up rules and tracking before each test."""
        super().setUp()
        post_peerid = get_table('filter').get_chain('post_peerid')
        post_peerid.rules = []
        # Clear the global tracking dictionary
        from hathor.p2p.netfilter import utils
        utils._peer_id_to_rule_uuid.clear()

    def test_peer_id_blacklist(self) -> None:
        post_peerid = get_table('filter').get_chain('post_peerid')

        # Chain starts empty
        self.assertEqual(len(post_peerid.rules), 0)

        # Add two rules to reject peer ids
        blacklist = ['123', '456']
        add_peer_id_blacklist(blacklist)

        # Chain has two rules now
        self.assertEqual(len(post_peerid.rules), 2)

        # Check that the rules are what we expect
        for rule in post_peerid.rules:
            data = rule.to_json()
            self.assertEqual(data['chain']['name'], 'post_peerid')
            self.assertEqual(data['match']['type'], 'NetfilterMatchPeerId')
            self.assertIn(data['match']['match_params']['peer_id'], blacklist)
            self.assertEqual(data['target']['type'], 'NetfilterReject')

    def test_add_blacklist_peers_with_list(self) -> None:
        """Test adding multiple peers with a list."""
        post_peerid = get_table('filter').get_chain('post_peerid')

        # Initially empty
        self.assertEqual(len(post_peerid.rules), 0)
        self.assertEqual(list_blacklist_peers(), [])

        # Add peers
        peer_ids = ['peer1', 'peer2', 'peer3']
        added = add_blacklist_peers(peer_ids)

        # All peers should be added
        self.assertEqual(sorted(added), sorted(peer_ids))
        self.assertEqual(len(post_peerid.rules), 3)
        self.assertEqual(sorted(list_blacklist_peers()), sorted(peer_ids))

    def test_add_blacklist_peers_with_string(self) -> None:
        """Test adding a single peer with a string."""
        post_peerid = get_table('filter').get_chain('post_peerid')

        # Add single peer
        peer_id = 'single_peer'
        added = add_blacklist_peers(peer_id)

        self.assertEqual(added, [peer_id])
        self.assertEqual(len(post_peerid.rules), 1)
        self.assertEqual(list_blacklist_peers(), [peer_id])

    def test_add_blacklist_peers_skip_duplicates(self) -> None:
        """Test that adding duplicate peers is skipped."""
        post_peerid = get_table('filter').get_chain('post_peerid')

        # Add peers first time
        peer_ids = ['peer1', 'peer2']
        added1 = add_blacklist_peers(peer_ids)
        self.assertEqual(sorted(added1), sorted(peer_ids))
        self.assertEqual(len(post_peerid.rules), 2)

        # Try to add same peers again
        added2 = add_blacklist_peers(peer_ids)
        self.assertEqual(added2, [])  # Nothing added
        self.assertEqual(len(post_peerid.rules), 2)  # Still 2 rules

        # Add mix of new and existing
        added3 = add_blacklist_peers(['peer1', 'peer3'])
        self.assertEqual(added3, ['peer3'])  # Only new peer added
        self.assertEqual(len(post_peerid.rules), 3)

    def test_add_blacklist_peers_skip_empty(self) -> None:
        """Test that empty strings are skipped."""
        peer_ids = ['peer1', '', 'peer2', '']
        added = add_blacklist_peers(peer_ids)

        self.assertEqual(sorted(added), ['peer1', 'peer2'])
        self.assertEqual(sorted(list_blacklist_peers()), ['peer1', 'peer2'])

    def test_remove_blacklist_peers_with_list(self) -> None:
        """Test removing multiple peers with a list."""
        # Add peers first
        peer_ids = ['peer1', 'peer2', 'peer3']
        add_blacklist_peers(peer_ids)
        self.assertEqual(sorted(list_blacklist_peers()), sorted(peer_ids))

        # Remove some peers
        to_remove = ['peer1', 'peer3']
        removed = remove_blacklist_peers(to_remove)

        self.assertEqual(sorted(removed), sorted(to_remove))
        self.assertEqual(list_blacklist_peers(), ['peer2'])

    def test_remove_blacklist_peers_with_string(self) -> None:
        """Test removing a single peer with a string."""
        # Add peers first
        add_blacklist_peers(['peer1', 'peer2'])

        # Remove one peer
        removed = remove_blacklist_peers('peer1')

        self.assertEqual(removed, ['peer1'])
        self.assertEqual(list_blacklist_peers(), ['peer2'])

    def test_remove_blacklist_peers_nonexistent(self) -> None:
        """Test removing peers that don't exist."""
        # Add one peer
        add_blacklist_peers('peer1')

        # Try to remove nonexistent peers
        removed = remove_blacklist_peers(['peer2', 'peer3'])

        self.assertEqual(removed, [])
        self.assertEqual(list_blacklist_peers(), ['peer1'])

        # Remove mix of existing and nonexistent
        removed2 = remove_blacklist_peers(['peer1', 'peer2'])
        self.assertEqual(removed2, ['peer1'])
        self.assertEqual(list_blacklist_peers(), [])

    def test_remove_blacklist_peers_skip_empty(self) -> None:
        """Test that empty strings are skipped during removal."""
        add_blacklist_peers(['peer1', 'peer2'])

        removed = remove_blacklist_peers(['peer1', '', 'peer2'])

        self.assertEqual(sorted(removed), ['peer1', 'peer2'])
        self.assertEqual(list_blacklist_peers(), [])

    def test_list_blacklist_peers(self) -> None:
        """Test listing blacklisted peers."""
        # Initially empty
        self.assertEqual(list_blacklist_peers(), [])

        # Add some peers
        peer_ids = ['peer1', 'peer2', 'peer3']
        add_blacklist_peers(peer_ids)
        self.assertEqual(sorted(list_blacklist_peers()), sorted(peer_ids))

        # Remove one
        remove_blacklist_peers('peer2')
        self.assertEqual(sorted(list_blacklist_peers()), ['peer1', 'peer3'])

        # Remove all
        remove_blacklist_peers(['peer1', 'peer3'])
        self.assertEqual(list_blacklist_peers(), [])
