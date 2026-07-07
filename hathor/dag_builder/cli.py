# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.dag_builder.builder import DAGBuilder


def main(filename: str, genesis_seed: str) -> None:
    from hathor.reactor import initialize_global_reactor

    # reactor
    _ = initialize_global_reactor(use_asyncio_reactor=False)

    from hathor.conf.get_settings import get_global_settings
    from hathor.daa import DAAFactory
    from hathor.nanocontracts.catalog import NCBlueprintCatalog
    from hathor.wallet import HDWallet
    settings = get_global_settings()

    def wallet_factory(words=None):
        if words is None:
            words = ('bind daring above film health blush during tiny neck slight clown salmon '
                     'wine brown good setup later omit jaguar tourist rescue flip pet salute')
        hd = HDWallet(words=words)
        hd._manually_initialize()
        return hd

    genesis_wallet = wallet_factory(genesis_seed)
    daa_factory = DAAFactory(settings=settings)
    nc_catalog = NCBlueprintCatalog()
    blueprints = NCBlueprintCatalog.generate_blueprints_from_settings(settings)
    nc_catalog.register_blueprints(blueprints)

    builder = DAGBuilder(
        settings=settings,
        daa_factory=daa_factory,
        genesis_wallet=genesis_wallet,
        wallet_factory=wallet_factory,
        vertex_resolver=lambda x: None,
        nc_catalog=nc_catalog,
    )

    fp = open(filename, 'r')
    content = fp.read()
    artifacts = builder.build_from_str(content)

    for node, vertex in artifacts.list:
        print('//', node)
        print('//', repr(vertex))
        print('//', node.name)
        print(bytes(vertex).hex())
        print()


if __name__ == '__main__':
    import os
    import sys
    if 'HATHOR_CONFIG_YAML' not in os.environ:
        os.environ['HATHOR_CONFIG_YAML'] = './hathor/conf/testnet.yml'
    genesis_seed = os.environ['GENESIS_SEED']
    main(sys.argv[1], genesis_seed)
