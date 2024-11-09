from hathor.dag_builder.builder import DAGBuilder
from hathor.dag_builder.tokenizer import parse_file


def main(filename, genesis_seed):
    from hathor.reactor import initialize_global_reactor

    # reactor
    _ = initialize_global_reactor(use_asyncio_reactor=False)

    from hathor.conf.get_settings import get_global_settings
    from hathor.daa import DifficultyAdjustmentAlgorithm
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
    daa = DifficultyAdjustmentAlgorithm(settings=settings)

    builder = DAGBuilder()
    tokenizer = parse_file(filename)
    it = builder.build(tokenizer, settings, daa, genesis_wallet, wallet_factory)

    for node, vertex in it:
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
