- Feature Name: fullnode_tps_benchmark
- Start Date: 2026-06-02
- RFC PR:
- Hathor Issue:
- Author: <fill in your name> <lfsrsprofessional@gmail.com>

# Summary
[summary]: #summary

This RFC proposes a small, modular benchmarking engine that measures how fast a single Hathor
full node can *process* the transactions it receives. Instead of talking to the node over the
network, the engine runs inside the same Python process as a real `HathorManager`, builds a batch
of valid transparent transactions, and feeds them one at a time through the node's own
vertex-processing pipeline — from deserialization through verification, storage, and consensus —
while timing each step and watching the node's resource usage. The output is a single, defensible
"transactions per second" number for node processing, broken down by pipeline stage, together with
plots and CSV/spreadsheet reports. The first version focuses narrowly on transparent transactions
on one thread; it is built so that other transaction types and other cost sources (wallet, relay,
confirmation) can be added later as opt-in modules.

# Motivation
[motivation]: #motivation

We keep being asked a deceptively simple question: *how many transactions per second can Hathor
handle?* The honest answer is "it depends on which part of the system you mean." A wallet that emits
transactions, the network that relays them, and the full node that validates and stores them are
three very different bottlenecks. This RFC isolates the one that matters most for capacity: **the
full node's ability to accept and process a transaction once it arrives.**

We want this for three reasons:

1. **A trustworthy ceiling.** When a node receives a transaction it does a fixed amount of CPU-bound
   work on a single thread (deserialize, verify signatures, run consensus, write to RocksDB). That
   per-transaction cost sets a hard ceiling on single-node throughput. We want to *measure* that
   cost rather than guess it, and to know where the time goes.
2. **Finding bottlenecks.** A per-stage breakdown tells us whether the node is spending its time in
   signature verification, in consensus bookkeeping, in storage, or somewhere surprising. (Our
   earlier code study already flagged two suspects — signature verification scaling with the number
   of inputs, and the fact that full verification appears to run *twice* per accepted transaction —
   and we want numbers to confirm or dismiss them.)
3. **A reusable, repeatable tool.** This should not be a one-off script. We want something we can
   re-run when the code changes, point at different transaction shapes, and eventually extend to
   nano contracts, fee-based tokens, and shielded outputs — so the same harness keeps answering the
   question as the protocol grows.

The expected outcome of the first milestone is concrete: a reproducible run that emits a headline
processing-TPS figure, a per-stage latency profile, a batch-level resource summary (memory, disk
I/O, file descriptors), and the charts to back them up.

# Guide-level explanation
[guide-level-explanation]: #guide-level-explanation

Think of the engine as a test bench for the part of the node that handles an incoming transaction.
The rest of this section walks through what that means, one idea at a time.

## 1. What we benchmark

We measure **the node, not the network.** A normal benchmark would fire HTTP requests at `push_tx`
and time the responses, but that measures the round trip, the web server, and the operating system's
networking — none of which we care about here, and all of which add noise. We want the node's
*internal* work, so the engine stands up a genuine node in-process using the same `Builder` the real
node uses, and then calls the node's processing functions directly. From the node's point of view
nothing is faked: it is a real `HathorManager` with real RocksDB storage, running the real
verification and consensus code.

It helps to be clear up front about how to *read* the resulting number. It is the node's **processing
ceiling on a single thread**, measured in isolation. It is deliberately not the wallet's emission
rate, not the network's relay rate, and not how fast blocks confirm — those are separate questions the
engine is designed to grow into, but they are out of scope for the first version. And because the node
processes transactions one at a time on a single reactor thread, the throughput is essentially the
reciprocal of the per-transaction processing time: the way to make the node faster is to make each
transaction cheaper, not to push more in parallel.

## 2. A transaction's journey in a node

A transaction's journey through the node breaks naturally into six steps. We give them stable names so
we can talk about them and chart them:

- **S1 — Deserialize:** the raw bytes become a transaction object.
- **S2 — Pre-checks:** the cheap rejects (already known? double spend? spending a voided tx?).
- **S3+S4 — Verify:** the real work — proof-of-work is *checked* (not solved), signatures are
  validated, balances must add up.
- **S5 — Save & consensus:** the transaction is written to storage and woven into the DAG (marking
  inputs as spent, updating the mempool tips).
- **S6 — Post-consensus:** indexes are updated and events are published.

The engine's whole job is to run a transaction through S1–S6 and record how long each stage took and
what it cost.

## 3. Workload

We describe what we want to push through — for the first version, "N transparent transactions, each
with `I` inputs and `O` outputs" — and the engine builds exactly that. It leans on hathor-core's own
**`DAGBuilder`**, a test-fixture generator that mines some funding blocks and then assembles N valid,
signed transactions of the requested shape. Importantly, `DAGBuilder` carries its **own** signing keys
and plays the role of the *sender*: the node under test never signs anything, it only verifies — which
keeps the wallet-versus-node boundary this whole project rests on perfectly clean.

A word on proof-of-work, because it is easy to misread. Every Hathor transaction carries a **weight**,
and the node will only accept it if that weight meets a minimum the node derives from the
transaction's size and amount. "Mining" a transaction means searching for a nonce whose hash clears
the target implied by that weight — and it is the *sender's* job, done before the transaction is ever
submitted. The node never mines an incoming transaction; it only *verifies* the proof-of-work.

For the benchmark we run the node in **test mode**, which relaxes that minimum, and we set every
transaction's **weight to 1**. We do this for one practical reason and one principled reason.

The practical reason is setup speed. Building the batch means finding a valid nonce for each of the N
transactions, and at a realistic weight that search is deliberately expensive. At weight 1 it is
effectively instant, so we can assemble a large batch quickly. And this all happens *before* the timed
loop — the nonce search lives in the build phase, outside the probes — so it never touches the
measurement in the first place.

The principled reason is that it does not meddle with the TPS result. From the processing node's
perspective the cost is **weight-independent**: verifying proof-of-work is a single constant-time
comparison of the hash against the target, and none of the other stages scale with the weight value
(the minimum the node computes in `verify_weight` depends on the transaction's size and amount, not on
the weight we chose). We could rebuild the batch at mainnet weight and the per-stage timings would
come out essentially the same; weight 1 simply spares us the setup cost for no measurement penalty.

## 4. Types of measurement

Not everything can be measured the same way, so the engine uses a different strategy per quantity.

**Time** is easy and precise. We wrap each stage and read a high-resolution clock before and after,
per transaction. That gives us clean per-stage timings and lets us draw histograms of, say, "how long
does verification take across 500 transactions."

**Memory, disk I/O, and file descriptors** are different animals. Memory does not change neatly per
transaction (the allocator works in pages and holds onto freed memory); disk writes in RocksDB are
*deferred* to a background flush rather than happening the instant we call save; and file-descriptor
counts barely move from one transaction to the next. So for these three we trust the **batch** view:
run the whole batch, then report the totals and peaks across it — total bytes written to disk, peak
memory, peak open files.

**A background time-series** runs alongside the batch. A sampler records memory/FDs/IO every fraction
of a second, which is what lets us draw "consumption over time" and "consumption versus number of
transactions" curves.

**A diagnostic overlay** keeps the crude per-stage memory/IO deltas too, clearly labelled as
low-confidence. Tellingly, the per-stage disk-I/O reads near zero — which is itself a nice visual
confirmation that writes are deferred, rather than a measurement failure.

## 5. An example

A Hathor dev writes a small config — `N=500, I=1, O=2` — and runs the engine. It boots a throwaway
node, funds a wallet, builds 500 single-input/two-output transactions, and then feeds them through
S1–S6 on one thread, recording the per-stage timings for every one and watching the node's resource
usage across the batch. From the dev's side it is a single command; everything else is automatic and
reproducible.

## 6. Visualizing

When the run finishes it writes a timestamped run folder. Inside is a `summary.md` with the headline
number (e.g. "processing throughput ≈ X tx/s"), a histogram per stage, a couple of time-series plots,
a "throughput vs N" chart from a batch-size sweep, and the raw data as CSV and a spreadsheet.

The point of laying it out this way is that the dev can open the summary and immediately see both
things that matter: the ceiling (how many transactions per second), and where the time went (which
stage dominates). The plots back up the headline so the number is never just asserted.

# Reference-level explanation
[reference-level-explanation]: #reference-level-explanation

The engine rests on a small number of load-bearing facts. Stated compactly:

1. The unit of measurement is **one vertex travelling through the node's processing pipeline**, which
   we divide into six named stages, **S1–S6**.
2. Each stage is *anchored* to exactly one real function in `hathor-core`. The engine times that
   function by wrapping it; it never reimplements the node's logic.
3. For a transaction, the entire pipeline is **synchronous and single-threaded**, so a stage's cost is
   simply the time between entering and leaving its anchor function — nothing is deferred to a later
   reactor tick.
4. **Time** is collected per-stage and per-transaction at high resolution. **Memory, disk I/O, and
   file descriptors** are collected per-*batch* (totals and peaks) plus a coarse background
   time-series, because those quantities are too noisy to pin to a single stage.
5. The node under test is a **real `HathorManager`** built with the production `Builder` on real
   RocksDB storage. Only two things are altered from a mainnet node: proof-of-work difficulty is set
   to the trivial test weight (1), and the network is absent.

## The pipeline and its anchor functions

When a transaction reaches a node, control flows through a fixed chain of calls. The engine attaches
its probes to the **bold** functions below; file references point into `hathor-core`.

```text
PushTxResource.handle_push_tx                       transaction/resources/push_tx.py:69
  ├─ vertex_parser.deserialize(tx_bytes)            ← S1   (bytes → Transaction)
  └─ HathorManager.push_tx(tx)                       manager.py:828
       ├─ tx_storage.transaction_exists(tx.hash)    ┐
       ├─ tx.is_double_spending()                   ├ S2   (the cheap rejects)
       ├─ tx.is_spending_voided_tx()                │
       ├─ is_spent_reward_locked(settings, tx)      ┘
       └─ HathorManager.on_new_tx(tx)                manager.py:872
            └─ VertexHandler.on_new_relayed_vertex(tx)            vertex_handler.py:129
                 └─ VertexHandler._old_on_new_vertex(tx, params)  vertex_handler.py:155
                      ├─ _validate_vertex(tx, params)             ← S3+S4   :185
                      │     └─ VerificationService.validate_full(tx, params)
                      ├─ _unsafe_save_and_run_consensus(tx)       ← S5      :217
                      │     ├─ tx_storage.save_transaction(tx)
                      │     └─ consensus.unsafe_update(tx)
                      └─ _post_consensus(tx, params, events)      ← S6      :232
                            └─ validate_full(tx, params)   # the SECOND pass
```

Two properties of this chain are what make the measurement honest.

First, **every function on it is synchronous.** They return plain values — `bool`,
`list[ConsensusEvent]`, `None` — never a Twisted `Deferred`. The asynchronous `@inlineCallbacks`
path exists only for *blocks* (`VertexHandler.on_new_block`), not for transactions. So "time spent in
S5" is exactly the wall-clock interval inside `_unsafe_save_and_run_consensus`, with no hidden
continuation running later.

Second, **`validate_full` is invoked twice** — once inside `_validate_vertex` (our S3+S4) and again
inside `_post_consensus` (our S6). By anchoring the two verification probes on those *outer* methods
rather than on `validate_full` itself, the two passes fall into different stages, and we can report
the cost of the redundant second verification as a first-class number instead of silently
double-counting it. This is the single most important reason the probe points are chosen where they
are.

The expensive work that S3+S4 pays for lives one level deeper, in `VerificationService._verify_tx`
(`verification/verification_service.py:240`):

- `verify_pow` — a single big-integer comparison against the target. The node *checks* the
  proof-of-work; it never solves it. Effectively free.
- `verify_inputs` — the secp256k1 signature checks and script execution. This is the dominant cost,
  and the one that grows linearly with the number of inputs `I`.
- `verify_transparent_balance` — inputs and outputs must sum correctly per token.

## Stage map

| Stage | Anchor function (probe site) | What is being paid for |
| :---- | :--------------------------- | :--------------------- |
| **S1** | `manager.vertex_parser.deserialize(raw)` | parse bytes into a vertex object |
| **S2** | pre-check block in `HathorManager.push_tx` | existence / double-spend / spending-voided / reward-lock |
| **S3+S4** | `VertexHandler._validate_vertex` | full verification: PoW check, **signatures**, balance |
| **S5** | `VertexHandler._unsafe_save_and_run_consensus` | RocksDB write + DAG/consensus bookkeeping + mempool tips |
| **S6** | `VertexHandler._post_consensus` | **second** verification pass + index updates + pubsub events |

## Standing up the node

The harness builds a real node with the production `Builder`, points storage at a throwaway RocksDB
directory, and flips the DAA into test mode so the required weight is 1. The node is built **without
relying on any embedded wallet** — `HathorManager` does carry an optional internal wallet for legacy
reasons, but we deliberately do not use it: signing belongs to the fixture generator (next
subsection), and the node only ever *verifies*. (Exact builder method names are confirmed during
implementation; the shape is what matters here.)

```python
from hathor.builder import Builder
from hathor.daa import TestMode

artifacts = (
    Builder()
    .set_network("testnet")
    .use_rocksdb()                       # internally RocksDBStorage.create_temp()
    .build()                             # note: no wallet attached to the node
)
manager = artifacts.manager
manager.daa.TEST_MODE = TestMode.TEST_TX_WEIGHT     # required tx weight → 1
manager.start()
```

## Building the workload

A workload is produced behind a tiny interface so that future transaction types slot in without
touching the driver:

```python
class TxSource(Protocol):
    def build(self, n: int, n_inputs: int, n_outputs: int) -> list[tuple[Transaction, bytes]]:
        ...
```

The transparent source builds its fixtures with hathor-core's **`DAGBuilder`** (`hathor/dag_builder/`),
the project's own test-DAG generator. Two properties make it the right tool. First, `DAGBuilder` **owns
its own wallets** — a `genesis_wallet` plus a `wallet_factory` — and signs the inputs itself
(`vertex_exporter.sign_all_inputs`), so the keys belong to the fixture generator standing in for the
sender; the node never signs. Second, it emits fully valid, signed, PoW-resolved vertices in
topological order, which is exactly what the probed loop consumes.

We describe the batch in `DAGBuilder`'s small DSL, generated programmatically: a run of funding blocks,
then per transaction one spending edge for each input (`b.out[k] <<< txi`) and one line for each output
(`txi.out[j] = v HTR`). `DAGBuilder.from_manager` resolves every vertex's nonce through
`manager.cpu_mining_service.resolve` (instant at weight 1). We pull the finished vertices out of
`artifacts.list`, process the funding blocks as untimed setup, and keep each transaction *alongside its
serialized bytes* — because S1 re-parses those bytes inside the timed loop.

```python
class DagBuilderTxSource:
    def build(self, n, n_inputs, n_outputs):
        dag = DAGBuilder.from_manager(
            self.manager,
            genesis_words=GENESIS_WORDS,
            wallet_factory=make_hd_wallet,        # the builder's OWN keys, not the node's
        )
        artifacts = dag.build_from_str(self.render_dsl(n, n_inputs, n_outputs))

        blocks = [v for _, v in artifacts.list if v.is_block]      # funding → setup
        txs    = [v for _, v in artifacts.list if not v.is_block]  # what we measure
        self.preload_blocks(blocks)                                # land funding in storage first

        return [(tx, bytes(tx)) for tx in txs]                     # S1 re-parses the bytes

    def render_dsl(self, n, n_inputs, n_outputs) -> str:
        # emits, programmatically:
        #   blockchain genesis b[1..M]            (M sized from n * n_inputs)
        #   b{k}.out[0] <<< tx{i}                 (one spending edge per input  → I inputs)
        #   tx{i}.out[{j}] = {v} HTR              (one line per output          → O outputs)
        ...
```

Everything is seeded (fixed `genesis_words`, a deterministic `wallet_factory`, test-reactor
timestamps), so a given config reproduces the same vertices on every run.

**Fallback.** `DAGBuilder` is the primary path, but it is built for hand-crafted topologies, so if the
generated DSL turns out to be awkward for a precise, very large uniform batch, the harness can instead
build each transaction directly with `wallet.prepare_transaction(Transaction, ins, outs)` +
`cpu_mining_service.resolve`, using a **harness-owned `HDWallet`** (again, the sender's keys — not the
node's). This is kept only as an escape hatch.

## The probe and the per-transaction record

A stage probe is a context manager that records both wall time and CPU time into the transaction's
record. Two clocks are kept because, although the path is single-threaded (so they are usually close),
their difference is exactly what reveals any time lost to I/O wait rather than computation.

```python
@dataclass
class StageTiming:
    wall_ns: int
    cpu_ns: int

@dataclass
class TxRecord:
    index: int
    tx_id: str
    n_inputs: int
    n_outputs: int
    size_bytes: int
    accepted: bool
    stages: dict[str, StageTiming]        # keys: "S1", "S2", "S3S4", "S5", "S6"

@contextmanager
def stage(rec: TxRecord, name: str):
    w0, c0 = time.perf_counter_ns(), time.process_time_ns()
    try:
        yield
    finally:
        rec.stages[name] = StageTiming(time.perf_counter_ns() - w0,
                                       time.process_time_ns() - c0)
```

## The driver loop

The driver replays the `_old_on_new_vertex` chain by hand, with a `stage(...)` around each anchor.
Calling the inner `VertexHandler` methods directly (rather than the public `on_new_tx`) is what lets
us slice the single internal call into the five measured intervals — this is precisely "where the
code triggers":

```python
vh = manager.vertex_handler
for i, (tx, raw) in enumerate(batch):
    rec = TxRecord(i, tx.hash_hex, n_inputs, n_outputs, len(raw), False, {})

    with stage(rec, "S1"):
        vtx = manager.vertex_parser.deserialize(raw)

    with stage(rec, "S2"):
        run_precheck(manager, vtx)        # existence / double-spend / voided / reward-lock

    params = build_verification_params(manager, vtx)
    with stage(rec, "S3S4"):
        ok = vh._validate_vertex(vtx, params)
    with stage(rec, "S5"):
        events = vh._unsafe_save_and_run_consensus(vtx)
    with stage(rec, "S6"):
        vh._post_consensus(vtx, params, events, quiet=True)

    rec.accepted = ok
    collector.add(rec)
```

## Measuring memory, disk I/O, and file descriptors

These three are read around the *batch*, not inside the loop. A background sampler thread (which only
reads `/proc`, so the processing thread stays alone in doing real work) records the time-series, and a
`flush()` after the loop forces RocksDB's deferred writes onto disk so they are actually counted.

```python
@dataclass
class BatchResources:
    wall_s: float
    io_read_bytes: int        # /proc/self/io delta across the batch
    io_write_bytes: int
    rss_peak_bytes: int       # max over sampler ticks (cross-checked with VmHWM)
    rss_growth_bytes: int     # rss_end - rss_start
    fd_peak: int              # max open file descriptors over the batch
    sst_bytes: int            # rocksdb total_sst_files_size, read after flush

def run_batch(manager, batch, sampler_interval_s=0.1) -> BatchResources:
    proc = psutil.Process()
    io0, rss0 = proc.io_counters(), proc.memory_info().rss
    sampler = Sampler(proc, sampler_interval_s).start()     # background /proc reader

    drive_loop(manager, batch)                              # the single-thread S1..S6 loop

    manager.tx_storage.flush()                              # realise deferred writes
    sampler.stop()
    io1 = proc.io_counters()
    return BatchResources(
        wall_s          = sampler.elapsed_s,
        io_read_bytes   = io1.read_bytes  - io0.read_bytes,
        io_write_bytes  = io1.write_bytes - io0.write_bytes,
        rss_peak_bytes  = sampler.rss_peak,
        rss_growth_bytes= proc.memory_info().rss - rss0,
        fd_peak         = sampler.fd_peak,
        sst_bytes       = read_total_sst_size(manager),     # via storage sysctl
    )
```

The authoritative resource numbers are the fields above. The per-stage memory/IO deltas the loop can
*also* capture are kept only as a diagnostic overlay — and the fact that the per-stage `io_write` for
S5 reads ≈ 0 is itself the visible proof that writes are deferred, not a measurement failure.

## Deriving the headline number

Throughput is the reciprocal of per-transaction cost, summed over the batch:

```python
processing_tps = N / sum(rec.stages[s].wall_ns for rec in records for s in STAGES) * 1e9
```

We report `processing_tps`, plus `1 / mean(per-tx total)`, the full latency distribution, and each
stage's share of the total. A batch-size sweep (N = 100, 500, 1k, 5k, …) yields the "throughput vs N"
and "consumption vs N" curves, which show whether per-transaction cost stays flat or creeps up as the
DAG, the UTXO set, and the mempool grow — an effect we expect to surface in verification reads
(`verify_inputs` touching more storage) and mempool-tip maintenance.

Node **energy** is modelled, not measured (no reliable RAPL counters under WSL/containers):
`energy ≈ Σ(per-stage CPU-seconds) × TDP × utilization`, with the constants declared in the run config
so the assumption is explicit in the report. The mining-energy term (`2^weight × J/hash`) is trivial
at weight 1 and reported only for completeness.

## Throughput is bounded by block cadence — the M/Tb model (and a measurement confound)

A single batch number is **not** a network rate, and treating it as one is the easiest way to get this
wrong. Here is why, and how we propose to read the benchmark correctly.

**The mempool-growth problem.** If we drive transactions without ever adding a block, the unconfirmed
mempool grows without bound. Consensus (S5) scales with the unconfirmed mempool, so the *per-tx* cost
climbs as the batch proceeds, and the perceived throughput keeps falling: "I sent 100 → 120 tx/s" but
"I sent 200 → 80 tx/s." In real Hathor this never runs away, because **blocks arrive about every
`Tb` seconds** (DAA-adjusted, order of tens of seconds) and confirm the mempool, resetting the
between-blocks transaction count `M`. Mainnet today is block-dominated (far more blocks than txs), so
each tx effectively arrives to a near-empty mempool — close to the *clean-slate* cost.

**Two numbers, not one.** Let `C(N)` be the cumulative processing time for a batch of `N` (mempool
growing 0→N) — exactly what the driver records. Then `perceived_TPS(N) = N / C(N)`, a decreasing curve.

- **Clean-slate ceiling** `1 / τ₀` (τ₀ = per-tx total at an empty mempool): the optimistic upper bound.
- **Sustainable rate** `M / Tb`: the node can clear at most the `M` txs whose cumulative cost fills a
  block interval, i.e. `C(M) = Tb`. Geometrically, on the `perceived_TPS`-vs-`N` plot the line
  `Y = N/Tb` (slope **1/Tb**, not 1) crosses the curve exactly at `(M, M/Tb)`, since
  `N/Tb = N/C(N) ⟺ C(N) = Tb`. We report `M/Tb` as a small table over `Tb ∈ {7.5, 15, 30, 60, 90} s`.

Because per-tx cost grows ~linearly with the mempool, `C(N)` is ~quadratic, so the sustainable rate is
far below the clean-slate ceiling and **rises as `Tb` shrinks** (more frequent blocks reset the mempool
sooner) — block cadence is a first-order lever on tx throughput.

**Status: this model is a HYPOTHESIS, not yet validated — and the current workload confounds it.** A
CP-4 block-reset experiment (drive M txs → inject one block → drive M more) did **not** confirm that a
block resets S5. The cause is the workload, not the node: our transparent batch parents every tx to
**genesis**, so the mempool is a *disconnected fan*. A block selects 2 tips as parents and transitively
confirms only what is reachable from them — with genesis-parenting, just those ~2 txs (measured: a block
confirmed 2 of 251). Worse, feeding genesis-parented txs into a chain that has advanced by a block sends
consensus into a pathological state (per-tx S5 jumped ~10 ms → ~120 ms). So the earlier "S5 grows with
M" figures are **provisional/inflated**, and the M/Tb model cannot be tested until the workload builds
an **organic, tip-confirming DAG** (each tx confirms 2 recent tips, like real traffic), so that (a) a
block sweeps the whole reachable mempool and (b) consensus traverses a realistic connected DAG.

**A second, non-resettable component.** S6 (`_post_consensus`) is the 2nd `validate_full` (∝ inputs)
plus index updates. The **mempool-tips** index is resettable by a block, but the **non-critical
indexes** (utxo / address / timestamp) grow with *total* stored txs and are **never** reset — a
permanent storage-scaling cost the M/Tb model does not capture. We should therefore split S6 reporting
into "re-verify" vs "index" sub-costs and track the permanent part against storage size.

**Plan (prerequisite-ordered):** (1) build the organic tip-confirming workload; (2) re-run the
block-reset experiment to validate (or refute) the M/Tb model and measure how much a block actually
resets; (3) tabulate `C(N)` and per-stage times across `N` (1…1000) and the resulting `M/Tb` for each
`Tb`, with plots; (4) measure the block's own O(M) confirmation cost and fold it into the `Tb` budget
(`C(M) + block_confirm(M) ≤ Tb`).

## Example

A single transaction from an `N=500, I=1, O=2` run produces a record like this (illustrative shape,
not measured values):

```json
{
  "index": 312, "tx_id": "00ab…", "n_inputs": 1, "n_outputs": 2,
  "size_bytes": 219, "accepted": true,
  "stages": {
    "S1":   {"wall_ns":  18000, "cpu_ns":  18000},
    "S2":   {"wall_ns":  42000, "cpu_ns":  41000},
    "S3S4": {"wall_ns": 610000, "cpu_ns": 600000},   ← signatures dominate
    "S5":   {"wall_ns": 130000, "cpu_ns": 120000},
    "S6":   {"wall_ns": 540000, "cpu_ns": 530000}    ← the second validate_full
  }
}
```

and the run's `summary.md` reduces the 500 records plus the `BatchResources` into a table of the form:

| Metric | Value (illustrative) |
| :----- | :------------------- |
| processing throughput | ≈ N / Σ time tx/s |
| median S3+S4 (verify) | … µs |
| median S6 (post-consensus) | … µs |
| S6 ÷ (S3+S4) (redundant-verify ratio) | ≈ 0.8–1.0 |
| peak RSS / RSS growth | … MB / … MB |
| total bytes written (after flush) | … MB |
| peak open file descriptors | … |

## Engine layout

The package lives at `tps_benchmarking/benchmarks/engine/` inside `hathor-core`, so it shares the
poetry environment and can `import hathor` directly. Its seams mirror this section: `node/` (the
harness), `workload/` (the `TxSource` implementations), `probes/` (the stage probe, the sampler, the
storage stats), `driver/` (the loop), `metrics/` (the records and collector), and `analysis/` (CSV,
spreadsheet, histograms, time-series, performance charts, `summary.md`). A thin CLI runs a scenario
from a YAML config and writes a timestamped run folder.

## Corner cases worth stating plainly

- **Deferred writes.** `save_transaction` only touches an in-memory cache, so the per-stage S5
  disk-I/O number is not faithful and is diagnostic only; the real figure is the batch total taken
  after the boundary `flush()`.
- **Background threads.** The sampler and RocksDB's own flush/compaction threads exist, so "single
  threaded" describes the *processing* path. Compaction cost surfaces in the batch `/proc` totals and
  is acknowledged as not attributable to any one stage.
- **Page-granular memory.** A single small transaction may show zero RSS change and then a 4 KB jump
  later; this is exactly why memory is reported at the batch level, not per stage.
- **Funding scale.** The fan-out must mint at least `N × I` coins; the harness sizes it from the
  requested workload before the timed loop begins.

# Drawbacks
[drawbacks]: #drawbacks

There are honest reasons to be cautious about this approach.

It **couples to the node's internals.** By wrapping methods like `_validate_vertex` and
`_post_consensus`, the engine depends on private functions whose names and boundaries can change
between hathor-core versions; an internal refactor could quietly break the stage mapping. A
network-level benchmark would not have this fragility.

It **measures a deliberately partial picture.** By skipping the network, the HTTP layer, and the
wire serialization of incoming requests, the engine excludes real costs that a deployed node actually
pays. The number it produces is a clean *processing* ceiling, not an end-to-end one, and it must
always be reported with that caveat or it will be misread.

It runs with **trivial proof-of-work** (weight 1). This does not bias the processing numbers — the
node only *verifies* proof-of-work, in constant time, so its per-transaction cost is independent of
the weight — but it does mean the bench is silent about the *emission* side, where real weights make
the sender's mining the true bottleneck. Anyone quoting the figure must keep node-processing
throughput and emission throughput separate.

The **probes themselves cost something.** Wrapping every stage of every transaction adds overhead, and
while timing overhead is small and measurable, it is not zero; the engine must account for it and
avoid heavy probes (like per-stage `tracemalloc`) in the hot path.

Finally, it is **single-node and single-thread by construction.** It says nothing about how a fleet of
nodes behaves, and it will not catch problems that only appear under real concurrency or real network
conditions.

# Rationale and alternatives
[rationale-and-alternatives]: #rationale-and-alternatives

The design's central choice is **in-process, white-box measurement**, and it is the best fit because
the question is specifically "where does the node spend its time processing a transaction." Only by
calling the node's own functions can we attribute time to individual stages; an external benchmark can
see the total but never the breakdown.

Several alternatives were weighed:

- **Black-box over HTTP `push_tx`.** Simple and realistic for an end-to-end number, but it cannot see
  inside the pipeline, and it folds in web-server and OS-networking noise that has nothing to do with
  processing cost. We keep this idea in our back pocket for a future "end-to-end acceptance" load, but
  it cannot answer the per-stage question.
- **Full white-box, per-stage memory and I/O for every transaction.** Tempting because it would
  produce the literal per-stage table, but forcing a flush and a `tracemalloc` snapshot at every stage
  boundary distorts the very timings we care about and serializes I/O artificially. Measuring those
  three resources at the batch level is *more* faithful, not less, because the per-event noise
  averages out.
- **In-memory storage.** Gives the cleanest CPU/time signal and perfect single-threading, but it is
  not how a real node runs and it produces zero disk and FD activity, so the storage cost — a real
  part of the answer — would simply vanish. We keep it available only as an optional CPU-only baseline.
- **Reusing the built-in `SimpleCPUProfiler` alone.** The node already ships a profiler with a `/top`
  endpoint, and we do lean on its existing `@cpu.profiler` markers for orientation. But it samples on
  a multi-second interval and aggregates by function, which is far too coarse for per-transaction,
  per-stage timing. Our own high-resolution probes are necessary; the built-in profiler is
  complementary.

The impact of not doing this is simply that our claims about Hathor's processing ceiling and its
bottlenecks would remain qualitative. We already have a careful *theoretical* study of the pipeline;
this engine is what turns those hypotheses into measured numbers.

# Prior art
[prior-art]: #prior-art

Within Hathor, the building blocks already exist and we deliberately reuse them rather than reinvent.
The node ships a `SimpleCPUProfiler` with a `/top` resource and a Prometheus exporter, which proves
the team already values in-node observability; our engine is a finer-grained, purpose-built
complement. The repository also contains a `Simulator`, a `tx_generator`, a `DAGBuilder` DSL for
constructing test DAGs, and the test helpers that mine blocks and build transactions — all of which we
stand on. There is an `extras/benchmarking` area aimed at sync, but nothing today measures single-node
transaction *processing* per stage, which is the gap this RFC fills.

Outside Hathor, the pattern is well trodden. Bitcoin Core maintains a dedicated `bench/`
micro-benchmark suite for hot paths like signature checking and script validation; go-ethereum has
extensive in-process Go benchmarks; and the broader Python ecosystem has `pytest-benchmark` and `asv`
for exactly this style of "call the real function in a loop and measure it" work. The lesson from
those communities is consistent: micro-benchmarks that call internal functions directly are the right
tool for attributing cost to stages, provided you are disciplined about reporting what they do and do
not include — which is why this RFC is so explicit about scope. The reciprocal relationship we rely on
(throughput equals one over per-item latency for serial work) is textbook queueing intuition rather
than anything novel; it simply happens to be the crux of why a single-threaded node's processing rate
is bounded the way it is.

# Unresolved questions
[unresolved-questions]: #unresolved-questions

Some things we expect to settle while building and running the first version:

- The right **energy constants** (TDP and utilization) for the analytical model, and whether a
  measured-RAPL pass is worth adding later where the hardware supports it.
- The **fan-out sizing** for very large N, and whether extremely long runs need the workload
  regenerated in waves to keep timestamps and funding healthy.
- Whether the **diagnostic per-stage memory/IO deltas** earn their keep or should be dropped in favour
  of batch totals plus the time-series alone.

Some things are deliberately **out of scope** for this RFC and left for the future: wallet emission
cost, relay to peers, multi-node latency, block confirmation timing, and every transaction type other
than simple transparent transfers. They are not problems to solve here; they are the next modules.

One risk we will need to watch rather than resolve up front: the engine's **coupling to private
methods** in the processing path. If hathor-core refactors those boundaries, the stage mapping will
need updating, and we should keep the probe layer small and well-documented so that stays cheap.

# Future possibilities
[future-possibilities]: #future-possibilities

The whole design is shaped so that the basic version is the first slice of something larger.

The most natural extension is **more transaction types.** The workload sits behind a small `TxSource`
interface precisely so that token-creation, nano-header (nano contract), fee-header, and shielded
(amount-hidden and fully-shielded) transactions can be added as new builders without touching the
driver or the metrics. Each new type will exercise different parts of verification, and the same
per-stage machinery will immediately show where their extra cost lands.

The second axis is **more cost sources.** Today the engine measures the node in isolation; the
architecture anticipates opt-in "load" modules that bolt on the pieces we deliberately excluded —
the wallet's emission and signing time, the relay-to-peers step, inter-node latency, and the time for
a block to actually confirm a transaction. Turning these on one at a time lets us build up from the
node's processing ceiling toward a realistic end-to-end picture, while always being able to point at
exactly which layer a cost belongs to.

Beyond that, a few ideas worth recording even though they are out of scope now: a small **control-panel
UI** so a user can pick a configuration and watch plots and data files appear on the fly; wiring the
engine into **CI as a regression gate** so a pull request that makes transaction processing slower
gets flagged automatically; running the same workload at **mainnet-like weights** to show the realism
curve between trivial and production proof-of-work; and, should hathor-core ever move verification off
the single reactor thread, using this same harness to quantify what parallel verification actually
buys. None of these justify the current RFC on their own; they simply describe the shape of the road
this first step is pointed down.
