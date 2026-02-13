# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from hathor.dag_builder.builder import DAGBuilder


def main(filename: str, genesis_seed: str) -> None:
    from hathor.reactor import initialize_global_reactor

    # reactor
    _ = initialize_global_reactor(use_asyncio_reactor=False)

    from hathor.conf.get_settings import get_global_settings
    from hathor.daa import DifficultyAdjustmentAlgorithm
    from hathor.nanocontracts.catalog import generate_catalog_from_settings
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
    nc_catalog = generate_catalog_from_settings(settings)

    builder = DAGBuilder(
        settings=settings,
        daa=daa,
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
        from hathor.transaction.vertex_parser import vertex_serializer
        print(vertex_serializer.serialize(vertex).hex())
        print()


if __name__ == '__main__':
    import os
    import sys
    if 'HATHOR_CONFIG_YAML' not in os.environ:
        os.environ['HATHOR_CONFIG_YAML'] = './hathor/conf/testnet.yml'
    genesis_seed = os.environ['GENESIS_SEED']
    main(sys.argv[1], genesis_seed)
