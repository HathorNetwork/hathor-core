import os

os.environ['HATHOR_CONFIG_FILE'] = 'hathor.conf.local'

from hathor.graphviz import GraphvizVisualizer
from hathor.p2p.peer_id import PeerId
from hathor.simulator import Simulator, FakeConnection, MinerSimulator, RandomTransactionGenerator
from hathor.simulator.attacker import AttackerSimulator
from hathor.transaction.scripts import P2PKH
from hathor.conf import HathorSettings

settings = HathorSettings()

simulator = Simulator(9922163193306864793)
simulator.start()

print('Simulation seed config:', simulator.seed)

peer_id1 = PeerId()
manager1 = simulator.create_peer(peer_id=peer_id1)
manager1.allow_mining_without_peers()

graphviz = GraphvizVisualizer(manager1.tx_storage, include_funds=False, include_verifications=True, only_blocks=True)

miner1 = simulator.create_miner(manager1, hashpower=1e9)
miner1.start()

simulator.run(3600)

for _ in range(20):
    print('')

blk = manager1.tx_storage.get_best_block()
graphviz.labels[blk.hash] = 'first_block'

meta = blk.get_metadata()
p2pkh = P2PKH.parse_script(blk.outputs[0].script)

print('Mining address:', p2pkh.address)
print('Block height:', meta.height)

print('Number of blocks:', manager1.wallet.get_total_tx())
print('Balance:', manager1.wallet.balance[settings.HATHOR_TOKEN_UID])

for _ in range(20):
    print('')

simulator.run(3600)

attacker = AttackerSimulator(manager1, simulator.rng, first_block=blk, hashpower=2e9)
attacker.start()

simulator.run(3600)

cnt = 1
for blk in attacker.hidden_blocks:
    manager1.propagate_tx(blk, fails_silently=False)
    dot = graphviz.dot()
    dot.render(f'dot_output/dot{cnt:05d}')
    cnt += 1


print(a)

tx_gen1 = simulator.create_tx_generator(manager1, rate=1., hashpower=1e6, ignore_no_funds=True)
tx_gen1.start()

simulator.run(600)

graphviz.labels[tx_gen1.latest_transactions[0]] = 'mytx'

for _ in range(20):
    print('')


print('Latest transactions:', [tx_hash.hex() for tx_hash in tx_gen1.latest_transactions])

# dot = graphviz.dot()
# dot.render('dot0')
