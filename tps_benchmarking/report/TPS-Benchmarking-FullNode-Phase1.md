<div class="cover">
<p class="cover-kicker">TECHNICAL REPORT</p>
<h1 class="cover-title">TPS‑Benchmarking<br>Full Node</h1>
<p class="cover-phase">Phase 1</p>
<hr class="cover-rule"/>
<p class="cover-sub">Measuring the transaction‑processing capacity of a Hathor full node</p>
<p class="cover-date">June 5, 2026</p>
<p class="cover-author">Luis Felipe Silva Rezende Soares</p>
</div>

<div class="pagebreak"></div>

## 2. Abstract

This report presents the first phase of a project to quantify the **transactions‑per‑second (TPS)** a
Hathor full node can process. We built a small, reusable, in‑process **white‑box micro‑benchmark** that
stands up a real `HathorManager` and drives valid transactions through the node's own
vertex‑processing pipeline, decomposed into six stages (S1–S6), while timing each stage and sampling
resource usage (RAM, disk I/O, file descriptors). On the reference machine (Intel i5‑11300H, single
thread) the node processes a baseline 1‑input / 2‑output transparent transaction at **≈ 215 tx/s**,
dominated not by a single stage but by **verification performed twice** (once in S3+S4 and again inside
post‑consensus) together with consensus bookkeeping. We characterise how the rate scales with
transaction shape — **inputs are expensive (≈ 2.6 ms each, roughly linear), outputs are cheap** — and
show that, with a representative tip‑confirming workload, per‑transaction cost is **bounded** in batch
size (no runaway growth), unlike a naïve genesis‑parented workload which degrades as O(N²). The number
is a single‑thread processing ceiling and **must be scaled to other hardware**; the methodology, the
findings, and their limitations are documented so the work can be extended (wallet emission, network
relay, shielded / nano / fee transactions) in later phases.

<div class="pagebreak"></div>

## 3. Introduction & Motivation

A recurring question about any blockchain is deceptively simple: *how many transactions per second can
it handle?* The honest answer is **"it depends which part of the system you mean."** A wallet emitting
transactions, the peer‑to‑peer network relaying them, and the full node validating and storing them are
three different bottlenecks with three different ceilings. This project isolates the one that sets the
hard limit on single‑node capacity: **the full node's ability to accept and process a transaction once
it arrives**, and — by extension — what that implies for the Hathor Network as a whole.

We pursue this for three reasons. First, a **trustworthy ceiling**: when a node receives a transaction
it performs a fixed amount of CPU‑bound work on a single thread (deserialize, verify signatures, run
consensus, write to storage); that per‑transaction cost caps single‑node throughput, and we want to
*measure* it rather than guess. Second, **bottleneck discovery**: a per‑stage breakdown reveals whether
the time goes to signature verification, consensus bookkeeping, or storage — and confirms or refutes
specific suspicions (notably, that full verification runs *twice* per accepted transaction). Third, a
**reusable tool**: not a one‑off script but an engine we can re‑run as the code evolves, point at
different transaction shapes, and grow to cover nano contracts, fee tokens, and shielded outputs.

To make the measurement legible, a transaction's journey through the node is divided into six named
**stages** — S1 Deserialize, S2 Pre‑checks, S3+S4 Verify, S5 Save & Consensus, S6 Post‑consensus. These
stages are the backbone of the whole study: every number we report is attributed to one of them, and the
engine exists to drive a transaction through S1–S6 and record how long each step takes and what it
costs. The remainder of this report explains how we built that instrument, what it measures, the
results, and the boundaries of what those results mean.

<div class="pagebreak"></div>

## 4. Methodology

### 4.1 Machine Specifications

All measurements in this report were obtained on a single reference machine:

| Component | Specification |
|---|---|
| CPU | Intel **Core i5‑11300H** (Tiger Lake, 11th gen), 4 cores / 8 threads, 3.10 GHz base / 4.40 GHz boost |
| Cores used | **One core, single thread** (the node processes vertices serially on one reactor thread) |
| RAM | **12 GB** (the benchmark's resident set stayed ≈ 100–110 MB) |
| OS | **Windows 11** host, running **WSL 2.0** (Ubuntu); Python 3.11 |
| Storage | RocksDB on a temporary directory (NVMe‑backed) |

> **⚠️ IMPORTANT — every throughput figure in this report is specific to this hardware and MUST be
> scaled to the reader's own machine before it means anything. Processing is single‑thread CPU‑bound, so
> the rate scales (approximately linearly) with single‑thread CPU performance, *not* with core count.
> To project these numbers to a different node, multiply by the ratio of single‑thread performance
> scores — e.g. PassMark's *Single Thread Rating* from cpubenchmark.net (PassMark Software):
> `TPS_target ≈ TPS_here × (single_thread_score_target / single_thread_score_i5‑11300H)`.**

### 4.2 Setup and Workflow

This is the heart of the methodology: how a real node is instantiated, instrumented, and fed.

#### 4.2.1 The six processing stages

When a transaction reaches the node it flows through a fixed pipeline. We time each step:

- **S1 — Deserialize.** Raw bytes become a vertex object (`vertex_parser.deserialize`).
- **S2 — Pre‑checks.** Cheap rejections: is it already known, is it a double‑spend, does it spend a
  voided transaction, is it spending a still‑locked block reward.
- **S3 + S4 — Verify.** The substantive work: proof‑of‑work is *checked* (not solved), every input
  signature is validated, and inputs must balance outputs (`VertexHandler._validate_vertex` →
  `validate_full`).
- **S5 — Save & Consensus.** The transaction is written to RocksDB and woven into the DAG: its inputs
  are marked spent, voided‑status is propagated, the **mempool‑tips index** is updated, and indexes are
  refreshed (`_unsafe_save_and_run_consensus`).
- **S6 — Post‑consensus.** Indexes and events are finalised — and, crucially, **`validate_full` is run a
  *second* time** (`_post_consensus`), so verification effectively happens twice per accepted tx.

#### 4.2.2 Probing hathor‑core: the node, the DAGBuilder, and how we drive them

Rather than fire HTTP requests at `push_tx` — which would measure the web server, the OS network stack,
and round‑trip latency, none of which we care about — the engine stands up a **genuine node in the same
Python process**. It uses hathor‑core's own test `Builder` to construct a real `HathorManager` with
**real RocksDB storage** and the **real verification and consensus code**; the network is set to
`unittests` and the difficulty‑adjustment is put in a test mode that sets every weight to 1, so
proof‑of‑work is trivial to *produce* (this affects only batch *setup*, never the measured cost, since
the node only *verifies* PoW — a single constant‑time hash comparison that is independent of the weight
value).

The workload is generated with hathor‑core's **`DAGBuilder`**, a test‑fixture engine that, from a small
text description, mines funding blocks and assembles valid, signed transactions of a requested shape.
Importantly, `DAGBuilder` carries its **own** signing keys and plays the role of the *sender*: the node
under test never signs anything, it only verifies — which keeps the wallet‑versus‑node boundary the
whole project rests on perfectly clean.

To time the stages individually, the driver **replays the node's own internal processing chain by hand**
(`VertexHandler._old_on_new_vertex`): it deserializes (S1), runs the manager pre‑checks (S2), then calls
`_validate_vertex` (S3+S4), `_unsafe_save_and_run_consensus` (S5) and `_post_consensus` (S6) in order,
wrapping each in a high‑resolution timer (`perf_counter_ns` for wall time, `process_time_ns` for CPU
time). These are the node's real functions, called in the node's real order — nothing is mocked.

#### 4.2.3 The setup workload (the most important construction)

A representative batch is built in three layers:

1. **Mining coinbase blocks.** A short chain of blocks is mined off genesis; each block carries a
   coinbase reward. These exist only to *create spendable value* and to satisfy the reward‑maturity rule
   (a coinbase cannot be spent until several blocks later).

2. **Funding transactions → inputs and outputs.** A small set of `fund` transactions consolidates the
   coinbase value and fans it out into many small, fully‑pinned UTXOs. Each payload transaction is then
   handed its **own disjoint slice** of those UTXOs as inputs (disjoint so no two transactions
   double‑spend), and emits pinned outputs whose values sum exactly to the inputs — so each transaction
   has *exactly* the requested I inputs and O outputs, with no surprises from the constraint solver. To
   keep this scalable, the fund transactions are **chained through their change outputs**, so the number
   of coinbase blocks required grows with total *value*, not with the UTXO count.

3. **Linear DAG parent‑chaining (the key correctness fix).** Every Hathor transaction confirms two
   "parents". A naïve workload lets the builder attach every transaction to *genesis*; the consequence
   is that **no transaction is ever a parent of another, so every transaction is a "tip"**, and since the
   node's consensus re‑scans *all* current tips on every transaction (`mempool_tips.update` is O(tips)),
   per‑transaction cost in **S5 grows linearly with the batch — an O(N²) blow‑up**. We avoid this by
   **chaining the transactions in the parent DAG** (`tx_k` names `tx_{k‑1}` as a parent), so each
   transaction confirms its predecessor and **only the latest transaction is ever a tip**. The tip set
   stays at ≈ 1, `mempool_tips.update` becomes O(1), and S5 is flat. (The fund transactions are likewise
   parent‑chained, to keep genesis from accumulating more children than a one‑byte counter can hold.)

The structure of the assembled workload, and the two edge types that connect it, are shown below.

```text
 LEGEND     ═══▶ spend  (consumes a UTXO — an input)        ──▶ parent  (confirms a vertex)

 (1) BLOCKS — mined off genesis to create coinbase value
       genesis ──▶ b1 ──▶ b2 ──▶ ··· ──▶ bn            (each  bi.out[0] = a coinbase reward)

 (2) FUNDS — consolidate the coinbases, fan the value into many small pinned UTXOs, and
             CHAIN through each fund's change output (so only a few blocks are needed)
       b1.out[0] ═╗
       b2.out[0] ═╬═══▶ fund0 ══change══▶ fund1 ══change══▶ ··· ══change══▶ fundM
          ···    ═╝       │                  │                                │
                      mints UTXOs        mints UTXOs                      mints UTXOs
                      out[0..199]        out[0..199]                      out[0..199]

 (3) PAYLOAD — each  txk  spends its OWN disjoint fund UTXOs (inputs) AND names the
              previous tx as a parent.  (Parent arrows point from a tx to its parent.)
                          fundF.out[k]
                               ║ spend
                               ▼
       genesis ◀── tx0 ◀── tx1 ◀── tx2 ◀── ··· ◀── tx(N-1)        ◀═══ the ONLY tip
                  (tx0,tx1     each tx confirms its predecessor
                   seed on     ⇒  tips ≈ 1  ⇒  mempool-tips scan is O(1)  ⇒  S5 stays flat
                   genesis)

 ── the pathology we AVOID ───────────────────────────────────────────────────────────
   If every tx parented GENESIS instead of the previous tx, then NO tx is anyone's
   parent ⇒ ALL N transactions are tips ⇒ the tip scan is O(N) ⇒ the batch costs O(N²):
       genesis ◀── tx0 , tx1 , tx2 , ··· , tx(N-1)     (a flat fan of N tips)
```

### 4.3 Data Collection and Treatment

For every transaction we record **per‑stage wall and CPU time** — the authoritative, primary signal.
Alongside, a background sampler reads Linux `/proc` to capture **memory** (resident set size, RSS),
**disk I/O** (actual block‑device read/write bytes), and **open file‑descriptor** counts over time; these
are reported as batch‑level totals and peaks. Throughout, **wall time ≈ CPU time**, confirming the path
is CPU‑bound (no idle I/O wait), which validates the timing.

Two treatments make the timing trustworthy. First, a **warm‑up prefix**: the first ~100 transactions are
driven but their records are *discarded*, because a cold RocksDB cache and a cold interpreter make the
opening transactions unrepresentatively slow; we report the steady state. Second, **windowed median
smoothing**: roughly **0.5 % of transactions are 5–20× slower** than normal (up to ~117 ms), and these
spikes are *entirely* in S5 — they are **RocksDB write‑stalls** (the storage engine periodically blocks a
write while it flushes/compacts). They are real background storage cost but not the steady per‑transaction
rate, so for trend curves we use a **rolling median** over a window (default 50, scaled down to 10 % of N
for small batches) which ignores the outliers, while still reporting the spike rate as tail latency.

<div class="pagebreak"></div>

## 5. Results

### 5.1 Headline figure and per‑stage profile

For the baseline 1‑input / 2‑output transparent transaction, the node's warmed, single‑thread
**processing rate is ≈ 215 tx/s (≈ 4.7 ms per transaction)**. The per‑stage breakdown (1-tip-transparent workload,
N = 500) is:

| Stage | Mean wall (µs) | Share | What dominates it |
|---|---|---|---|
| S1 Deserialize | 131 | 3 % | bytes → object |
| S2 Pre‑checks | 57 | 1 % | cheap rejects |
| S3+S4 Verify | 1007 | 24 % | **1st** full verification (PoW check, signatures, balance) |
| S5 Save & Consensus | 1856 | 44 % | consensus bookkeeping + storage write + indexes |
| S6 Post‑consensus | 1193 | 28 % | **2nd** full verification + indexes + events |
| **Total** | **4245** | | **→ ≈ 236 tx/s** |

The single most important structural finding: **verification runs twice** — once in S3+S4 and again
inside S6 — so verification‑related work is ≈ S3+S4 plus most of S6, i.e. **roughly half the total cost**,
more than pure consensus. The redundant second `validate_full` is the most concrete optimisation target
identified by this study.

### 5.2 Throughput over time, and the effect of warm‑up

The figure below drives 100 warm‑up + 10 000 measured transactions and plots the rolling throughput
across the whole run. The faint grey line is the rolling *mean* (the downward spikes are the RocksDB
write‑stalls); the bold line is the rolling *median*. Throughput rises from a cold start, crosses the
W = 100 warm‑up boundary, and settles into a steady regime — confirming both that the warm‑up prefix is
necessary and that, once warm, per‑transaction cost does **not** drift upward (it is bounded in N).

![Throughput vs transaction index — warm‑up rise to steady state](img/warmup.png)

### 5.3 How transaction shape changes the rate

**Inputs (I) dominate.** Sweeping I from 1 to 10 with O fixed at 2, the rolling‑median throughput drops
steeply and roughly linearly in cost — about **+2.6 ms per additional input**:

![Input sweep — rolling‑median TPS per input count (O = 2)](img/inputs.png)

| Inputs I | 1 | 2 | 3 | 4 | 5 | 10 |
|---|---|---|---|---|---|---|
| TPS | ~201 | ~132 | ~97 | ~77 | ~65 | ~32 |

The reason is structural and ties back to §5.1: **each input is verified twice** (a signature check in
S3+S4 *and* again in S6's second `validate_full`) **and** adds consensus input‑bookkeeping in S5
(`mark_inputs_as_used` loads and updates the spent transaction). So adding inputs inflates **S3+S4, S6,
and S5 together** — the cost grows on every front, hence the steep, near‑linear decline (a 5‑input
transaction costs ~3× a 1‑input one; a 10‑input one ~6×).

**Outputs (O) are cheap.** Sweeping O from 2 to 25 with I fixed at 1, throughput falls only gently:

![Output sweep — rolling‑median TPS per output count (I = 1)](img/outputs.png)

| Outputs O | 2 | 5 | 10 | 15 | 25 |
|---|---|---|---|---|---|
| TPS | ~203 | ~198 | ~175 | ~149 | ~131 |

Outputs are not verified the way inputs are — an output is essentially a value + a script record. Adding
them grows the serialized size and the balance sum slightly (a mild effect in S3+S4 and storage), but
there is no per‑output signature check and no consensus traversal. So **O reduces TPS, but far less than
I**: going O = 2 → 25 costs ~35 %, whereas I = 1 → 10 costs ~85 %. The practical takeaway is that a
transaction's *shape* — chiefly its input count — sets its cost, not merely its existence.

### 5.4 Resource usage and scaling

Throughout, CPU is the sole binding resource. Resident memory stayed at **≈ 100–110 MB** with only a few
MB of growth across thousands of transactions; disk writes totalled a few MB (after flushing deferred
writes); open file descriptors peaked at ~31 — all far from any system limit. Per‑transaction cost is
**bounded in batch size out to N = 10 000** (it even drifts slightly *down* as caches warm, never up),
the payoff of the tip‑confirming workload. Because that cost is flat, the sustainable rate is essentially
independent of block cadence: the node can clear whatever arrives between blocks at the same steady rate.

<div class="pagebreak"></div>

## 6. Limitations of the experiment

The figures here are honest but bounded, and should be read with these caveats:

- **Single machine — must be scaled.** Every number is specific to the i5‑11300H single‑thread
  performance and **must be re‑scaled to the target node's hardware** (see §4.1). Treat ≈ 215 tx/s as a
  point on a curve, not an absolute.
- **Linear (single‑tip) DAG.** Our workload chains transactions into a near‑linear DAG with ≈ 1 tip,
  whereas live Hathor traffic forms a mesh with typically **2–3 tips** (each transaction confirming two
  *recent* tips). The single‑tip shape is enough to remove the O(N²) artifact and measure steady cost,
  but it does not exercise the consensus tip‑management exactly as mainnet would, and may *hide* some
  behaviour that only appears with a wider tip frontier.
- **No mainnet synchronisation.** We run against a small, fresh temporary database, so resident memory
  sits at **≈ 100 MB**. A node synced to mainnet holds a far larger UTXO set, indexes, and cache —
  realistically **2–4–6 GB** — so our experiment **does not reveal the true RAM ceiling** a loaded node
  faces, nor the cache‑miss penalties a large database would impose on verification reads.
- **Time volatility.** The data is **highly fluctuant**: WSL 2 system load and background RocksDB
  compaction inject run‑to‑run variance (the headline rate ranges roughly 160–270 tx/s across runs), and
  the per‑transaction write‑stall spikes require median smoothing to interpret. The numbers are best read
  as *order‑of‑magnitude with a stated band*, not to two significant figures.

<div class="pagebreak"></div>

## 7. Further improvements (future phases)

The engine was built modular so the following can be added as opt‑in modules without disturbing the core:

- **Wallet emission latency.** Add the cost of a wallet *creating and signing* a transaction (and its
  per‑wallet send serialisation), to complement the node‑side number with the sender side.
- **Network / HTTP latency.** Measure the `push_tx` HTTP POST path and request/response round‑trip, to
  capture what an external submitter actually experiences.
- **Shielded transactions.** Privacy‑preserving (hidden‑amount / shielded‑output) transactions carry
  heavier cryptography and **will change TPS dramatically** — likely the single largest swing of any
  feature listed here.
- **Nano contracts and fee‑based tokens.** Smart‑contract execution and fee accounting add new
  per‑transaction work; both are natural next transaction types for the registry.
- **A more representative DAG.** A k‑tip‑frontier workload (each transaction confirming 2–3 recent tips)
  to match mainnet topology and re‑validate the consensus cost.
- **Removing the double verification.** Implement and measure the elimination of the redundant second
  `validate_full` — the clearest single‑threaded optimisation this study identified (~1.3× on its own).
- **Multi‑node and confirmation.** Inter‑node relay latency and block‑confirmation timing, to move from a
  single‑node processing ceiling toward a network‑level throughput figure.

## 8. Addendum — Phase 2: shielded outputs (preliminary)

The shielded‑transaction item above was the predicted "single largest swing." It is now **measured**. The
engine was extended (new `amount-shielded` / `full-shielded` transaction types) and run on a branch with
Hathor's confidential‑transactions implementation (Pedersen commitments + Borromean range proofs +
surjection proofs, native `secp256k1-zkp`). Same in‑process, single‑thread, 1-tip-transparent (tips≈1) methodology.

**Transparent vs shielded (I=1, O=2, 64‑bit range proofs; measured in one session, fresh node per row):**

| workload | processing TPS | S3S4 verify (µs) | serialized size |
|---|---|---|---|
| 1-tip-transparent | 177 | 1 807 | 291 B |
| amount‑shielded | 35 | 21 714 | 10.6 KB |
| full‑shielded | 36 | 21 386 | 10.8 KB |

The prediction held: shielded processing is **~5× lower throughput**, driven by a **~12× heavier
verification stage** and a **~36× larger transaction**. Key results:

- **Outputs are the expensive axis** (the mirror of the transparent finding, where *inputs*/signatures
  dominated): verification cost scales ~linearly with the number of shielded outputs — full‑shielded S3S4
  ≈ 18 / 31 / 67 ms for O = 2 / 4 / 8, with size ≈ +5.3 KB per shielded output.
- **Range‑proof verification dominates**; amount‑only and fully‑shielded are ~equal when the surjection
  domain is trivial. Bit‑width is a clean cost/size dial (40‑bit ≈ 13 ms / 7 KB vs 64‑bit ≈ 19 ms / 11 KB).
- **The double `validate_full` interacts specifically with shielded verification**: the expensive range
  proofs run **once** (basic‑phase, cached after S3S4), while the cheaper surjection + balance checks
  re‑run in S6. So removing the redundant second validation (§7) helps shielded *less* than transparent.

*(Absolute TPS here is noisier than the §5 ~215 baseline — these rows ran back‑to‑back on a loaded machine;
the ratios and per‑stage scaling are the result. Full tables: `benchmarks/engine/docs/shielded-results.md`.
Two upstream defects in the shielded implementation had to be fixed first — see `bugs-found/`.)*

---

*Phase 1 — engine, methodology, and baseline results (with a Phase‑2 shielded addendum). Generated from the
`hathor_tps_bench` benchmark engine; per‑stage timings, plots, and raw CSV/JSON are reproducible via the
engine's command‑line interface.*
