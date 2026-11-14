# Baseline results — Hathor full‑node processing TPS (Phase 1)

The first end‑to‑end answer the engine produces: **how fast can one Hathor full node *process*
transactions on its single processing thread?** Measured in‑process (real `HathorManager`, real
verifiers, RocksDB temp storage), per stage S1–S6, with a warm‑up prefix so the figures are steady
state. Transactions are transparent, organic (tip‑confirming) DAG.

## Setup

| | |
|---|---|
| Machine | Intel **i5‑11300H** (4c/8t, 3.1–4.4 GHz), 12 GB RAM, WSL2 |
| Method | in‑process driver, replays S1–S6 with `perf_counter`+`process_time`; warm‑up W=100 discarded |
| Workload | `organic` transparent, weight‑1 PoW (verify‑only cost is weight‑independent), RocksDB temp |
| TPS | `N / Σ(per‑tx total wall)` — single thread, no pipelining |

## Headline

For the baseline shape **I=1, O=2**, the warmed steady‑state rate is **~215 tx/s** (≈ 4.7 ms/tx),
single thread. Run‑to‑run it ranges ~160–270 tx/s depending on warm state and WSL2 system load — so the
honest figure is **~215 tx/s ± a wide band**, not a sharp number.

Per‑stage split (organic, flat across N):

| stage | share | what |
|---|---|---|
| S1 deserialize | ~3% | bytes → vertex |
| S2 pre‑checks | ~1% | exists / double‑spend / reward‑lock |
| S3S4 verify | ~27% | **1st** full verification (PoW, sigs, balance) |
| S5 save+consensus | ~37% | mark‑inputs / voided / mempool‑tips (O(1)) / save / indexes |
| S6 post‑consensus | ~31% | **2nd** full verification + indexes + events |

**Key finding — verification runs twice.** S3S4 *and* S6 both call `validate_full`, so
verification‑related work is ≈ S3S4 + most of S6 ≈ **half the per‑tx cost** — more than pure consensus.
That redundant 2nd `validate_full` is the single most concrete optimization target.

## Scaling with batch size N

Per‑tx cost is **bounded** — no growth with N out to **10,000** txs (within a run it actually drifts
*down* as caches warm; it never climbs):

| tx range (N=10000 run) | mean S5 µs | ~TPS |
|---|---|---|
| 1–2000 | 3646 | 150 |
| 4001–6000 | 3642 | 141 |
| 8001–10000 | 2166 | 207 |

This is the payoff of the **organic** workload. The earlier **genesis‑parented** workload was O(N²)
(per‑tx consensus = O(tip count), and every tx was a tip → tips = N): its TPS *collapsed* 169 → 36 from
N=100 → 1000. Organic keeps tips ≈ 1, so consensus is O(1) and TPS is N‑independent.

## I/O sweep — inputs dominate, outputs are cheap

| I:O | 1:2 | 2:2 | 3:2 | 4:2 | 5:2 | 1:3 | 1:4 | 1:5 |
|---|---|---|---|---|---|---|---|---|
| TPS | 247 | 144 | 110 | 83 | 69 | 236 | 235 | 217 |
| total µs | 4053 | 6926 | 9118 | 12001 | 14445 | 4238 | 4254 | 4612 |

Per‑tx cost ≈ **`base + ~2.6 ms × (I−1)`** — roughly linear in **inputs**, because every input pays a
signature verification (×2, S3S4+S6) plus consensus input bookkeeping. **Outputs are ~free** (O=2→5
barely moves TPS). So tx *shape*, not just count, sets the rate: a 5‑input tx costs ~3.5× a 1‑input one.

## M/Tb — sustainable rate vs block interval

Blocks arrive ~every `Tb` seconds and confirm the mempool. The sustainable rate is `M/Tb`, where `C(M)=Tb`
(M txs fill a block interval). Because organic per‑tx cost is **flat**, `C(N)` is linear, so **`M/Tb = 1/τ`
for every Tb** — the sustainable rate equals the steady rate, and **block cadence does not bound it**:

| Tb (s) | M (txs between blocks) | sustainable TPS |
|---|---|---|
| 7.5 | ~1600 | ~213 |
| 15 | ~3200 | ~213 |
| 30 | ~6400 | ~213 |
| 60 | ~12800 | ~213 |
| 90 | ~19100 | ~213 |

(Contrast: in the genesis O(N²) regime, `M/Tb` *falls* as Tb grows, because letting the mempool fill
longer makes each tx more expensive. Organic removes that coupling — the M/Tb model only "bites" when
consensus scales with mempool size, which it no longer does.)

## Scaling to other hardware

Processing is **single‑thread CPU‑bound** (wall ≈ cpu; memory ~110 MB, FDs ~31, disk a few MB — none
near a limit). So TPS scales ~linearly with **single‑thread** performance, and **extra cores do not add
tx‑processing throughput** (they help background compaction, not the serial pipeline):

```
TPS_target  ≈  215 × (single_thread_score_target / single_thread_score_i5‑11300H)
```

Illustrative (plug real single‑thread benchmark scores to refine):

| host class | rel. single‑thread | projected TPS |
|---|---|---|
| modern server / cloud vCPU (~this laptop) | ~1.0× | ~215 |
| high‑clock desktop/server | ~1.2× | ~260 |
| budget / older VPS | ~0.5× | ~110 |
| SBC (Raspberry‑Pi‑class) | ~0.25× | ~55 |

Hathor doesn't publish hard node minimums (the node is lightweight — runs under Docker on modest
hardware); the practical takeaway is that **single‑thread CPU is the lever**, and RAM/disk are not
binding at this workload.

## Parallelism & resource ceilings

**Threading doesn't help.** `wall ≈ cpu` ⇒ the thread never waits on I/O, so there's no idle time for a
second thread to fill (and CPython's GIL stops CPU‑bound threads running in parallel anyway). More
fundamentally, the node processes vertices **serially by design** — consensus mutates shared DAG/UTXO
state, so concurrent processing of overlapping txs would race.

**More cores: a ~2× ceiling, not free.** As‑is, extra cores do nothing (serial pipeline). Re‑architected,
**verification (S3S4+S6 ≈ ½ the cost) is embarrassingly parallel** (each tx's checks are local), so it
could be spread across cores with a serial commit (S5). By Amdahl, parallelizing ~50% caps speedup at
`1/(1−0.5) = 2×` (~430 tx/s); consensus's serial state‑mutation is the floor. Cheaper first: removing the
**redundant 2nd `validate_full`** is ~1.3× single‑threaded with no parallelism.

**Resource ceilings.** At this scale CPU is the sole bottleneck — RSS ~110 MB, disk a few MB, FDs 31, all
far from any limit. At mainnet scale:
- **RAM is the real cap, but it's a *cache* knob, not chain‑size.** The node keeps everything in RocksDB
  on disk; RAM = the tx‑object LRU (`--cache-size`, counts vertices) + RocksDB block cache + small
  in‑memory indexes + overhead → runs comfortably in **~2–4 GB**, set by cache config not by the millions
  of mainnet vertices (those are tens of GB of *disk*). Too small a cache → more of the **5 µs→90 µs
  cold‑read misses** we measured → lower real TPS; if RSS exceeds RAM → swap → collapse. (`--memory-storage`
  is the exception — it puts the whole DB in RAM and *does* scale with chain size; not for mainnet.)
- **Disk I/O / compaction** can bind *sustained* throughput on slow disks (HDD / capped IOPS); on NVMe,
  CPU binds first. Compaction also steals CPU (part of our run‑to‑run variance).
- **FDs**: minor — RocksDB opens FDs per SST file; far from the ulimit, trivially raised.

The engine **captures** all of these (sampler + batch resources), so the methodology is ready to flag when
they bind — today, CPU does.

## Caveats

- **Weight‑1 PoW** — verification cost is weight‑independent (a single hash compare), so this doesn't
  inflate the result; it only makes batch *setup* cheap.
- **WSL2 + background RocksDB compaction** — process‑wide CPU timing absorbs compaction, adding run‑to‑run
  variance; hence the band around 215.
- **Single machine, single thread, isolation** — no peer sync, relay, or block‑processing competing for
  the reactor; this is the *processing ceiling*, not a live‑network rate.
- **Double `validate_full`** is real per‑tx work here and the top optimization candidate.
