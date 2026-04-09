from hathor.nanocontracts.sorter.random_sorter import NCBlockSorter, SorterNode


def test_random_sorter_stable_order() -> None:
    seed = bytes.fromhex('0ccf87ef1e7307c3017413ce2477df54ed31d396792f0bfbef93aa7741949f2b')

    nc_hashes = set(bytes.fromhex(i) for i in [
        '0000142cf4351face7ff5803117f6d4c0375b0b724c576f7ffcbea7058fa9470',
        '00000fb45c8eeecbe2bc5ab69f8a1f88081a7739c813b7accefbf4a13ac5e37a',
        '00004151b4a5eed517d225da4be498ec29c3f61ecf1b72766a16ab952610af1b',
        '000049ba9ba45cf8dccaed7d05b8a383ca392b9329866531da9c45960e699f26',
        '00000e468cc227afe3999df597c49fa37ba527c2a6e2cdf1b9cfe3df67835cab',
        '00000060e9e2358566ad277e7750a016d09043ab53cc4ce7897e29631f5ad7ea',
    ])

    db = [
        SorterNode(
            id=bytes.fromhex('000049ba9ba45cf8dccaed7d05b8a383ca392b9329866531da9c45960e699f26'),
            outgoing_edges={
                bytes.fromhex('000003e0baf17eee5a25aa0ccf36eb331a05818c87bc1c316f54485aa974c485'),
                b'dummy:2',
            },
            incoming_edges=set(),
        ),
        SorterNode(
            id=bytes.fromhex('000003e0baf17eee5a25aa0ccf36eb331a05818c87bc1c316f54485aa974c485'),
            outgoing_edges=set(),
            incoming_edges={
                bytes.fromhex('0000142cf4351face7ff5803117f6d4c0375b0b724c576f7ffcbea7058fa9470'),
                bytes.fromhex('00000fb45c8eeecbe2bc5ab69f8a1f88081a7739c813b7accefbf4a13ac5e37a'),
                bytes.fromhex('00004151b4a5eed517d225da4be498ec29c3f61ecf1b72766a16ab952610af1b'),
                bytes.fromhex('000049ba9ba45cf8dccaed7d05b8a383ca392b9329866531da9c45960e699f26'),
                bytes.fromhex('00000e468cc227afe3999df597c49fa37ba527c2a6e2cdf1b9cfe3df67835cab'),
                bytes.fromhex('00000060e9e2358566ad277e7750a016d09043ab53cc4ce7897e29631f5ad7ea'),
            },
        ),
        SorterNode(
            id=bytes.fromhex('0000142cf4351face7ff5803117f6d4c0375b0b724c576f7ffcbea7058fa9470'),
            outgoing_edges={
                bytes.fromhex('000003e0baf17eee5a25aa0ccf36eb331a05818c87bc1c316f54485aa974c485'),
                b'dummy:2',
            },
            incoming_edges=set()
        ),
        SorterNode(
            id=bytes.fromhex('00004151b4a5eed517d225da4be498ec29c3f61ecf1b72766a16ab952610af1b'),
            outgoing_edges={
                bytes.fromhex('000003e0baf17eee5a25aa0ccf36eb331a05818c87bc1c316f54485aa974c485'),
                b'dummy:2',
            },
            incoming_edges=set(),
        ),
        SorterNode(
            id=bytes.fromhex('00000fb45c8eeecbe2bc5ab69f8a1f88081a7739c813b7accefbf4a13ac5e37a'),
            outgoing_edges={
                b'dummy:1',
                bytes.fromhex('000003e0baf17eee5a25aa0ccf36eb331a05818c87bc1c316f54485aa974c485'),
                bytes.fromhex('00000060e9e2358566ad277e7750a016d09043ab53cc4ce7897e29631f5ad7ea'),
            },
            incoming_edges={
                b'dummy:2',
            },
        ),
        SorterNode(
            id=bytes.fromhex('00000060e9e2358566ad277e7750a016d09043ab53cc4ce7897e29631f5ad7ea'),
            outgoing_edges={
                bytes.fromhex('00000e468cc227afe3999df597c49fa37ba527c2a6e2cdf1b9cfe3df67835cab'),
                b'dummy:0',
                bytes.fromhex('000003e0baf17eee5a25aa0ccf36eb331a05818c87bc1c316f54485aa974c485'),
            },
            incoming_edges={
                b'dummy:1',
                bytes.fromhex('00000fb45c8eeecbe2bc5ab69f8a1f88081a7739c813b7accefbf4a13ac5e37a'),
            },
        ),
        SorterNode(
            id=bytes.fromhex('00000e468cc227afe3999df597c49fa37ba527c2a6e2cdf1b9cfe3df67835cab'),
            outgoing_edges={
                bytes.fromhex('000003e0baf17eee5a25aa0ccf36eb331a05818c87bc1c316f54485aa974c485'),
                bytes.fromhex('00000717cb78166401aaf2db1a2cae645781bb255efa4ee6b1cf2daa5f390197'),
            },
            incoming_edges={
                b'dummy:0',
                bytes.fromhex('00000060e9e2358566ad277e7750a016d09043ab53cc4ce7897e29631f5ad7ea'),
            },
        ),
        SorterNode(
            id=bytes.fromhex('00000717cb78166401aaf2db1a2cae645781bb255efa4ee6b1cf2daa5f390197'),
            outgoing_edges=set(),
            incoming_edges={
                bytes.fromhex('00000e468cc227afe3999df597c49fa37ba527c2a6e2cdf1b9cfe3df67835cab'),
            },
        ),
        SorterNode(
            id=b'dummy:0',
            outgoing_edges={
                bytes.fromhex('00000e468cc227afe3999df597c49fa37ba527c2a6e2cdf1b9cfe3df67835cab'),
            },
            incoming_edges={
                bytes.fromhex('00000060e9e2358566ad277e7750a016d09043ab53cc4ce7897e29631f5ad7ea'),
            },
        ),
        SorterNode(
            id=b'dummy:1',
            outgoing_edges={
                bytes.fromhex('00000060e9e2358566ad277e7750a016d09043ab53cc4ce7897e29631f5ad7ea'),
            },
            incoming_edges={
                bytes.fromhex('00000fb45c8eeecbe2bc5ab69f8a1f88081a7739c813b7accefbf4a13ac5e37a'),
            },
        ),
        SorterNode(
            id=b'dummy:2',
            outgoing_edges={
                bytes.fromhex('00000fb45c8eeecbe2bc5ab69f8a1f88081a7739c813b7accefbf4a13ac5e37a'),
            },
            incoming_edges={
                bytes.fromhex('000049ba9ba45cf8dccaed7d05b8a383ca392b9329866531da9c45960e699f26'),
                bytes.fromhex('0000142cf4351face7ff5803117f6d4c0375b0b724c576f7ffcbea7058fa9470'),
                bytes.fromhex('00004151b4a5eed517d225da4be498ec29c3f61ecf1b72766a16ab952610af1b'),
            },
        ),
    ]

    sorter = NCBlockSorter(nc_hashes)
    for node in db:
        sorter.db[node.id] = node

    # XXX: not strictly necessary, whatever order we set must never change
    expected_order = list(bytes.fromhex(i) for i in [
        '00000e468cc227afe3999df597c49fa37ba527c2a6e2cdf1b9cfe3df67835cab',
        '00000060e9e2358566ad277e7750a016d09043ab53cc4ce7897e29631f5ad7ea',
        '00000fb45c8eeecbe2bc5ab69f8a1f88081a7739c813b7accefbf4a13ac5e37a',
        '00004151b4a5eed517d225da4be498ec29c3f61ecf1b72766a16ab952610af1b',
        '0000142cf4351face7ff5803117f6d4c0375b0b724c576f7ffcbea7058fa9470',
        '000049ba9ba45cf8dccaed7d05b8a383ca392b9329866531da9c45960e699f26',
    ])
    order = sorter.generate_random_topological_order(seed)
    assert order == expected_order

    # XXX: this is necessary to preserve the consensus of the mainnet
    tx1 = bytes.fromhex('0000142cf4351face7ff5803117f6d4c0375b0b724c576f7ffcbea7058fa9470')
    tx2 = bytes.fromhex('000049ba9ba45cf8dccaed7d05b8a383ca392b9329866531da9c45960e699f26')
    assert order.index(tx2) > order.index(tx1)
