from bisect import bisect_left
from typing import List, Optional


class BTreeIterator(object):
    def __init__(self, block, idx):
        self.block = block
        self.idx = idx

    def __iter__(self):
        return self

    def __next__(self):
        if self.idx >= len(self.block.children):
            raise StopIteration
        data = self.block.children[self.idx]
        if isinstance(data, BTreeBlock):
            self.block = data
            self.idx = 0
            data = self.block.children[self.idx]
        self.idx += 1
        return data


class BTreeBlock(object):
    """
    TODO Remove parent.
    TODO Add support to use a fixed length list for keys and children.
    """
    def __init__(self, *, is_leaf: bool = True):
        self.length: int = 0
        self.keys: List = []
        self.children: List[BTreeBlock] = []
        self.parent: Optional[BTreeBlock] = None
        self.is_leaf = is_leaf

    def get_child(self, index):
        return self.children[index]

    def dump(self, level=0):
        prefix = ' ' * (4 * level)
        print('{}[keys={}'.format(prefix, self.keys))
        if not self.is_leaf:
            for child in self.children:
                child.dump(level=level+1)
        else:
            for child in self.children:
                print('{}    data={}'.format(prefix, child))
        print('{}]'.format(prefix))

    def __len__(self):
        if self.is_leaf:
            return len(self.keys)

        return sum(len(child) for child in self.children)


class BTree(object):
    """
    """

    def __init__(self, max_children: int = 5):
        self.max_children = max_children
        self.center_idx = self.max_children // 2
        self.root: BTreeBlock = BTreeBlock()

    def _search(self, key):
        block = self.root
        while block is not None:
            if block.is_leaf:
                return block
            idx = bisect_left(block.keys, key)
            if idx >= len(block.children):
                return block
            block = block.children[idx]
        raise ValueError('Must never happen.')

    def get(self, key):
        block = self._search(key)
        idx = bisect_left(block.keys, key)
        if idx < len(block.keys) and block.keys[idx] == key:
            return BTreeIterator(block, idx)
        raise ValueError('{} not in tree'.format(key))

    def _add_node(self, block, key, data, *, flag: bool = False):
        idx = bisect_left(block.keys, key)
        if idx < len(block.keys) and block.keys[idx] == key:
            # Duplicate element.
            return

        idx_data = idx
        if flag:
            idx_data += 1

        if len(block.keys) < self.max_children:
            # Just add the key in the available slot.
            block.keys.insert(idx, key)
            block.children.insert(idx_data, data)
            return

        # Block is full. Let's split it.
        # [10, 20, 30]

        if idx <= self.center_idx:
            # When adding 15, then: [10, 15], [20, 30]
            split_idx = self.center_idx
        else:
            # When adding 25, then: [10, 20], [25, 30]
            split_idx = self.center_idx + 1

        b_right = BTreeBlock(is_leaf=not flag)
        b_right.parent = block.parent
        b_right.keys = block.keys[split_idx:]
        b_right.children = block.children[split_idx:]

        block.keys = block.keys[:split_idx]
        block.children = block.children[:split_idx]

        if b_right.is_leaf:
            # After the split, point to the next leaf.
            block.children.append(b_right)

        if idx <= self.center_idx:
            block.keys.insert(idx, key)
            block.children.insert(idx_data, data)
        else:
            idx -= split_idx
            idx_data -= split_idx
            b_right.keys.insert(idx, key)
            b_right.children.insert(idx_data, data)

        new_key = block.keys[-1]

        parent = block.parent
        if parent is not None:
            self._add_node(parent, new_key, b_right, flag=True)

        else:
            # If we don't have a parent, let's create one.
            parent = BTreeBlock(is_leaf=False)
            parent.keys = [new_key]
            parent.children = [block, b_right]
            block.parent = parent
            b_right.parent = parent
            self.root = parent

    def dump(self):
        self.root.dump()

    def add_node(self, key, data=None):
        if data is None:
            data = key
        block = self._search(key)
        self._add_node(block, key, data)

    def __len__(self):
        return len(self.root)
