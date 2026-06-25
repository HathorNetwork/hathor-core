"""
CP-11 de-risk spike: can a MIXED transaction — transparent AND shielded inputs, plus
transparent AND shielded outputs in one tx — be built via the DAGBuilder and pass FULL
verification? (The upstream unshield matrix test builds such txs but only checks header
layout; it never drives them through verify_shielded_balance. Our CP-7 reconciliation
patch handles shielded inputs in the residual, but mixed has never been driven end-to-end.)

Recipe (from test_unshield_balance_dag_builder.py): a source with only shielded outputs
exposes shielded output i at DSL out[i] (on-chain index len(outputs)+i = i here), so
`ssrc.out[0] <<< mix` spends a shielded output as a shielded INPUT.

Run:  cd tps_benchmarking/engine
      PYTHONPATH="<repo>:$PWD" <venv-python> spikes/spike_cp11_mixed.py
"""
from hathor.exception import InvalidNewTransaction
from hathor_tps_bench.node import NodeHarness

# 1 transparent in (50) + 1 shielded in (50) -> 1 transparent out (30) + 2 shielded out (34+34);
# fee = 2 (2 amount-shielded outputs x FEE_PER_AMOUNT_SHIELDED_OUTPUT=1). 100 == 30+34+34+2.
DSL = """
blockchain genesis b[1..50]
b30 < dummy

b1.out[0] <<< tfund
tfund.out[0] = 50 HTR
b25 < tfund

ssrc.out[0] = 50 HTR [shielded]
ssrc.out[1] = 50 HTR [shielded]
b25 < ssrc

tfund.out[0] <<< mix
ssrc.out[0] <<< mix
mix.out[0] = 30 HTR
mix.out[1] = 34 HTR [shielded]
mix.out[2] = 34 HTR [shielded]
b45 < mix
"""


def main() -> int:
    harness = NodeHarness(seed=1234, trivial_pow=True, shielded=True).start()
    try:
        manager = harness.manager
        artifacts = harness.dag_builder().build_from_str(DSL)
        result = {}
        for node, vertex in artifacts.list:
            if manager.tx_storage.transaction_exists(vertex.hash):
                continue
            try:
                ok = manager.vertex_handler.on_new_relayed_vertex(vertex)
                result[node.name] = "accepted" if ok else "rejected(False)"
            except InvalidNewTransaction as e:
                result[node.name] = f"REJECTED: {str(e)[:80]}"
                if node.name == "mix":
                    break

        mix = artifacts.get_typed_vertex("mix", __import__("hathor.transaction", fromlist=["Transaction"]).Transaction)
        n_sh_out = len(mix.shielded_outputs)
        n_in = len(mix.inputs)
        print(f"sources: tfund={result.get('tfund')}  ssrc={result.get('ssrc')}")
        print(f"mix tx : inputs={n_in} (1 transparent + 1 shielded), shielded_outputs={n_sh_out}, "
              f"transparent_outputs={len(mix.outputs)}")
        print(f"mix result: {result.get('mix')}")
        ok = result.get("mix") == "accepted"
        print(f"\nSPIKE RESULT: {'PASS ✓ mixed tx builds + verifies' if ok else 'FAIL ✗'}")
        return 0 if ok else 1
    finally:
        harness.stop()


if __name__ == "__main__":
    raise SystemExit(main())
