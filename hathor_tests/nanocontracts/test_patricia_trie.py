import hashlib
import tempfile
from math import log
from typing import Optional

from hathor.nanocontracts.storage.backends import RocksDBNodeTrieStore
from hathor.nanocontracts.storage.patricia_trie import Node, PatriciaTrie
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor_tests import unittest


def export_trie_outline(trie: PatriciaTrie, *, node: Optional[Node] = None) -> tuple[bytes, Optional[bytes], dict]:
    """Return the tree outline for testing purposes.

    The returned format is (key, value, list[children]) where each child has the same format.
    """
    if node is None:
        node = trie.root

    d = {}
    for k, child_id in node.children.items():
        child = trie.get_node(child_id)
        d[trie._decode_key(k)] = export_trie_outline(trie, node=child)
    return (trie._decode_key(node.key), node.content, d)


class PatriciaTrieTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        directory = tempfile.mkdtemp()
        self.tmpdirs.append(directory)
        self.rocksdb_storage = RocksDBStorage(path=directory)

    def create_trie(self) -> PatriciaTrie:
        store = RocksDBNodeTrieStore(self.rocksdb_storage)
        return PatriciaTrie(store)

    def test_empty_key(self) -> None:
        trie = self.create_trie()
        with self.assertRaises(KeyError):
            trie.get(b'')

    def test_empty_trie(self) -> None:
        trie = self.create_trie()
        with self.assertRaises(KeyError):
            trie.get(b'my-key')

    def test_single_key(self) -> None:
        trie = self.create_trie()
        key = b'my-key'

        with self.assertRaises(KeyError):
            trie.get(key)

        trie.update(key, b'1')
        trie.commit()
        self.assertEqual(trie.get(key), b'1')
        root1_id = trie.root.id

        trie.update(key, b'1')
        trie.commit()
        self.assertEqual(trie.get(key), b'1')
        self.assertEqual(root1_id, trie.root.id)

        trie.update(key, b'2')
        trie.commit()
        self.assertEqual(trie.get(key), b'2')

        self.assertNotEqual(root1_id, trie.root.id)
        self.assertEqual(trie.get(key, root_id=root1_id), b'1')

        n_nodes = len(trie._db)
        trie.update(key, b'1')
        trie.commit()
        self.assertEqual(trie.get(key), b'1')
        self.assertEqual(root1_id, trie.root.id)
        self.assertEqual(n_nodes, len(trie._db))

        trie.print_dfs()

        self.assertEqual(
            export_trie_outline(trie),
            (b'', None, {
                key: (key, b'1', {}),
            })
        )

    def test_independent_keys(self) -> None:
        trie = self.create_trie()

        key1 = b'\x00abcde'
        key2 = b'\x10fghijklmn'

        trie.update(key1, b'1')
        trie.commit()
        self.assertEqual(trie.get(key1), b'1')

        trie.update(key2, b'2')
        trie.commit()
        self.assertEqual(trie.get(key2), b'2')

        self.assertEqual(len(trie.root.children), 2)
        trie.print_dfs()

        self.assertEqual(
            export_trie_outline(trie),
            (b'', None, {
                key1: (key1, b'1', {}),
                key2: (key2, b'2', {}),
            })
        )

    def test_simple_chain(self) -> None:
        trie = self.create_trie()

        data = {
            b'a': b'1',
            b'abcd': b'2',
            b'ab': b'3',
            b'abcdefg': b'4',
            b'abcdefh': b'5',
        }
        for k, v in data.items():
            trie.update(k, v)
            # print('!! UPDATE', k)
            # print()
            # trie.print_dfs()
            # print()
            # print()
            # print()
            # print()

        for k, v in data.items():
            self.assertEqual(trie.get(k), v)
        trie.commit()

        self.assertEqual(
            export_trie_outline(trie),
            (b'', None, {
                b'a': (b'a', b'1', {
                    b'b': (b'ab', b'3', {
                        b'cd': (b'abcd', b'2', {
                            b'ef`': (b'abcdef`', None, {
                                b'p': (b'abcdefg', b'4', {}),
                                b'\x80': (b'abcdefh', b'5', {}),
                            }),
                        }),
                    }),
                }),
            })
        )

    def test_random_data(self) -> None:
        trie = self.create_trie()

        data = {}
        for v_int in range(20_000):
            v = str(v_int).encode('ascii')
            k = hashlib.sha256(v).digest()
            data[k] = v
            trie.update(k, v)

        for k, v in data.items():
            self.assertEqual(trie.get(k), v)
        trie.commit()

        max_children = max(len(x.children) for x, _, _ in trie.iter_dfs())
        max_height = max(h for _, h, _ in trie.iter_dfs())

        print('max_children', max_children)
        print('max_height', max_height)
        print('n_nodes', len(trie._db))

        self.assertLessEqual(max_children, 16)
        self.assertLessEqual(max_height, 2*log(len(data), 16))

    def test_commit(self) -> None:
        trie = self.create_trie()

        data = {}
        for v_int in range(20_000):
            v = str(v_int).encode('ascii')
            k = hashlib.sha256(v).digest()
            data[k] = v
            trie.update(k, v)
        trie.commit()
        root1_id = trie.root.id

        key1, value1 = next(iter(data.items()))
        trie.update(key1, value1 + b'1')
        self.assertTrue(trie.is_dirty())
        trie.commit()
        self.assertFalse(trie.is_dirty())
        root2_id = trie.root.id

        self.assertNotEqual(root1_id, root2_id)
        self.assertEqual(trie.get(key1, root_id=root1_id), value1)
        self.assertEqual(trie.get(key1, root_id=root2_id), value1 + b'1')

    def test_multiple_keys_same_value(self) -> None:
        trie = self.create_trie()
        data = {
            b'a': b'1',
            b'abcd': b'1',
            b'ab': b'1',
            b'abcdefg': b'1',
            b'abcdefh': b'1',
            b'\x01xyz': b'1',
        }
        for k, v in data.items():
            trie.update(k, v)
        trie.commit()

        for k, v in data.items():
            self.assertEqual(trie.get(k), v)
