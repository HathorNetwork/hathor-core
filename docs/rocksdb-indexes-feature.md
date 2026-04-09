# Feature: RocksDB indexes

## Introduction

This design describes basically how to add a new indexes backend in-disk using rocksdb besides our current in-memory backend.

## Motivation

The network is growing rapidly and the large number of transactions is increasing the memory usage of a full-node. It usually was enough to run a full-node with 8GB RAM, lately there have been cases with out-of-memory crashes with 8GB, so our recommendation increased to 16GB.

Secondarily, a full-node with an existing database will take a while (usually 10~50min) to start because no index is persisted and they have to be rebuilt on every start. Persisting the indexes across reboots will solve this really annoying behavior.

## Acceptance Criteria

- Have all indexes (except for the interval-tree ones, that will be removed with sync-v1) using the rocksdb backend by default
- Initially make RocksDB indexes opt-in
- Make sure the tests cover the new backend
- Persist the indexes across restarts (this can, and probably will, be implemented and released separately)

## Detailed explanation

### How to use rocksdb to persist indexes

Last July @msbrogli made a proof-of-concept implementation on #254 using rocksdb to persist the address-index(previously called wallet-index).

The main technique is using the sorted nature of rocksdb keys to implement queries that return sorted lists. This means that we can build the key such that when the key is are sorted, it also sorts the elements that we want to sort.

For example, the address-index sorts transactions by timestamp for each address, so the keys can be built as:

```
        key = [address][tx.timestamp][tx.hash]
              |--34b--||--4 bytes---||--32b--|
```

And then we iterate by `[address]` prefix and the keys will be sorted by (timestamp, hash) ([source](https://github.com/HathorNetwork/hathor-core/pull/254/files#diff-43ba4ce1c938bdda238c5751a95e43d7fe762507fd2db39382a9b4c22d3c88a1R145-R155)):

```python
    def _get_from_address_iter(self, address: str) -> Iterable[bytes]:
        self.log.debug('seek to', address=address)
        it = self._db.iterkeys(self._cf)
        it.seek(self._to_key(address))
        for _cf, key in it:
            addr, _, tx_hash = self._from_key(key)
            if addr != address:
                break
            self.log.debug('seek found', tx=tx_hash.hex())
            yield tx_hash
        self.log.debug('seek end')
```

### How to load persistent-indexes

The first implementation will simply reset all indexes when initializing (this is implemented by dropping the relevant column-families on rocksdb, which is an operation that has constant time `O(1)`), it's important to really make sure the index was successfully reset or fail initializing otherwise. This will still have the down-side of slow loading times but will significantly simplify the implementation and avoid introducing issues related to a change to the index initialization implementation.

The final solution will require the interval-tree indexes (which are all indexes that will not be ported to rocksdb) to support being rebuilt independently, that is without using the current loading machinery that relies on adding transactions to completely empty indexes. Once this is implemented "fast" loading can be enabled.
