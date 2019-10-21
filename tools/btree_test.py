
import unittest
from btree import BTree

class BTreeTestCase(unittest.TestCase):
    def test_duplicate(self):
        tree = BTree()
        tree.add_node(4)
        tree.add_node(4)
        tree.add_node(4)
        tree.add_node(4)
        tree.add_node(4)
        self.assertEqual(tree.root.keys, [4])
        self.assertEqual(len(tree), 1)
        self.assertEqual(tree._search(4), tree.root)

    def test_basic(self):
        tree = BTree(max_children=3)
        tree.add_node(2)
        tree.add_node(3)
        tree.add_node(1)
        self.assertEqual(tree.root.keys, [1, 2, 3])
        self.assertEqual(len(tree), 3)
        self.assertEqual(tree._search(0), tree.root)
        self.assertEqual(tree._search(1), tree.root)
        self.assertEqual(tree._search(2), tree.root)
        self.assertEqual(tree._search(3), tree.root)
        self.assertEqual(tree._search(4), tree.root)

        tree.add_node(1)
        self.assertEqual(tree.root.keys, [1, 2, 3])
        self.assertEqual(len(tree), 3)

        tree.add_node(4)
        self.assertEqual(tree.root.keys, [2])
        self.assertEqual(tree.root.children[0].keys, [1, 2])
        self.assertEqual(tree.root.children[1].keys, [3, 4])
        self.assertEqual(len(tree), 4)

        tree.add_node(5)
        self.assertEqual(tree.root.keys, [2])
        self.assertEqual(tree.root.children[0].keys, [1, 2])
        self.assertEqual(tree.root.children[1].keys, [3, 4, 5])
        self.assertEqual(len(tree), 5)

        tree.add_node(6)
        self.assertEqual(tree.root.keys, [2, 4])
        self.assertEqual(tree.root.children[0].keys, [1, 2])
        self.assertEqual(tree.root.children[1].keys, [3, 4])
        self.assertEqual(tree.root.children[2].keys, [5, 6])
        self.assertEqual(len(tree), 6)

        tree.add_node(7)
        self.assertEqual(tree.root.keys, [2, 4])
        self.assertEqual(tree.root.children[0].keys, [1, 2])
        self.assertEqual(tree.root.children[1].keys, [3, 4])
        self.assertEqual(tree.root.children[2].keys, [5, 6, 7])
        self.assertEqual(len(tree), 7)

        tree.add_node(8)
        self.assertEqual(tree.root.keys, [2, 4, 6])
        self.assertEqual(tree.root.children[0].keys, [1, 2])
        self.assertEqual(tree.root.children[1].keys, [3, 4])
        self.assertEqual(tree.root.children[2].keys, [5, 6])
        self.assertEqual(tree.root.children[3].keys, [7, 8])
        self.assertEqual(len(tree), 8)

        tree.add_node(9)
        self.assertEqual(tree.root.keys, [2, 4, 6])
        self.assertEqual(tree.root.children[0].keys, [1, 2])
        self.assertEqual(tree.root.children[1].keys, [3, 4])
        self.assertEqual(tree.root.children[2].keys, [5, 6])
        self.assertEqual(tree.root.children[3].keys, [7, 8, 9])
        self.assertEqual(len(tree), 9)

        tree.add_node(10)
        self.assertEqual(tree.root.keys, [4])
        self.assertEqual(tree.root.children[1].keys, [6, 8])
        block = tree.root.children[0]
        self.assertEqual(block.keys, [2, 4])
        self.assertEqual(block.children[0].keys, [1, 2])
        self.assertEqual(block.children[1].keys, [3, 4])
        block = tree.root.children[1]
        self.assertEqual(block.keys, [6, 8])
        self.assertEqual(block.children[0].keys, [5, 6])
        self.assertEqual(block.children[1].keys, [7, 8])
        self.assertEqual(block.children[2].keys, [9, 10])
        self.assertEqual(len(tree), 10)

        tree.add_node(2.5)
        tree.add_node(3.5)
        tree.dump()

        self.assertEqual(list(tree.get(8)), [8, 9, 10])
        self.assertEqual(list(tree.get(3.5)), [3.5, 4, 5, 6, 7, 8, 9, 10])
        self.assertEqual(list(tree.get(1)), [1, 2, 2.5, 3, 3.5, 4, 5, 6, 7, 8, 9, 10])


unittest.main()
