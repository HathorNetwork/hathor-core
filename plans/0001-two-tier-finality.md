# Implementation Plan: Two-Tier Finality (v1 — UTXO fast path)

## Context

RFC `internal-rfcs/projects/finality/0001-two-tier-finality.md` adds a sub-second **soft finality**
tier on top of Hathor's existing PoW **hard finality**. A fixed committee of *finality validators*
co-signs UTXO transactions: each validator, on first seeing a tx spending a UTXO, signs it and
**pins** that UTXO to it (never signs a conflicting spender). When signatures of weight `≥ 2f+1`
of total `3f+1` are collected they aggregate into a **Finality Certificate (FC)**. The binding rule:
**a PoW block is invalid if it confirms a transaction that conflicts with an already-certified one** —
so PoW *ratifies* the fast path and can never reverse a certified payment.

This plan covers **v1 only**: the UTXO fast path on a fixed PoA-style committee. Deferred to later
milestones/RFCs: PoS staking, economic slashing, fraud proofs, epoch governance/rotation,
epoch-boundary unlock, multi-owner griefing mitigation, the Nano-Contract total-order path, and PoW
tie-break resolution of *uncertified* wedged UTXOs (in v1 a wedged UTXO simply stays frozen, which
only harms the equivocator).

### Core transport model (per user direction)
The mempool is **certified-only**, and FC collection is **validator-driven** (this intentionally
deviates from the RFC's client-driven framing where validators never message one another):
- **Submission:** any node keeps a finality-eligible tx that lacks a quorum FC in a **pending-FC pool**
  and forwards it to **one or more validators — default: one random validator** — then waits for the
  certified version to return over the network. Pending txs are never in the mempool and never relayed
  to the general network by non-validators.
- **Collection (committee overlay):** validators are connected to each other and **gossip the pending
  tx + votes among themselves**. Each validator validates, **pins** the inputs, signs, floods its
  `VOTE`, and accumulates incoming votes in its pending pool.
- **Release:** the first validator to accumulate weight `≥ 2f+1` assembles the FC and **broadcasts the
  certified tx + FC to the entire network**.
- **Independent admission:** every node re-verifies the attached FC reaches quorum before admitting the
  tx to its own mempool and relaying onward — it never trusts an upstream peer. The FC travels
  *alongside* the tx (it signs over `tx_id`, so it cannot live inside the tx hash).

### Confirmed design decisions
- **Signatures:** BLS12-381 aggregate (codebase has no BLS today — a library is added).
- **Committee:** fixed set + weights in network settings, PoA-style, gated by feature activation.
- **FC transport:** certified-only mempool + validator-gossip collection as above; blocks additionally
  commit to an **FC root** (advisory in v1 — Component G).
- **Binding rule lives in consensus, not the verifier** (the confirmed-tx set only exists at
  consensus time). Verified in code: `_score_block_dfs` is where `first_block` is assigned.

### Key grounding facts (verified in code)
- Block confirmation sets `meta.first_block = block.hash` in
  `hathor/consensus/block_consensus.py::BlockConsensusAlgorithm._score_block_dfs` (the
  `mark_as_best_chain` branch) — the correct hook for the ratification rule + settlement signal.
- Mempool-admission / relay entry points: `hathor/vertex_handler/vertex_handler.py`
  (`on_new_mempool_transaction`, `on_new_relayed_vertex`, `_post_consensus` →
  `NETWORK_NEW_TX_ACCEPTED`); mempool sync in `hathor/p2p/sync_v2/`.
- Feature gating: `_should_execute_nano` → `Features.from_vertex(...).nanocontracts` (gates on parent).
- Conflict primitives to reuse: `TransactionMetadata.spent_outputs[index] -> [tx_hash,…]`,
  `Transaction.is_double_spending()` / `is_spending_voided_tx()`.
- Crypto/config/lifecycle to mirror: `hathor/consensus/poa/poa_signer.py`,
  `hathor/consensus/consensus_settings.py` (`PoaSettings`/`PoaSignerSettings`,
  `_calculate_peer_hello_hash`), `poa_block_producer.py`; index pattern in `hathor/indexes/`.
- p2p: `ProtocolMessages` + `ReadyState.cmd_map`; capability gating (`CAPABILITY_NANO_STATE`);
  per-line limit 65536 bytes (a vote/FC ≈100–130 bytes, fits one line); `iter_ready_connections()`
  for broadcast.
- Header extension: `VertexHeaderId`, `get_supported_headers` (gated on `settings.ENABLE_*`), headers
  fold into PoW hash via `get_graph_and_headers_hash`, `get_maximum_number_of_headers()` = 3.

---

## Architecture overview

```
 any node (submitter)        committee overlay (validators gossip among themselves)        whole network
 --------------------        -----------------------------------------------------         -------------
 pending-FC pool
   └─ forward to a RANDOM ──▶  v_i: validate + PIN inputs + sign ──flood tx + VOTE──▶ v_j,v_k…
      validator                each validator accumulates votes in its pending pool
   (await certified result)    first to reach ≥ 2f+1 weight → assemble FC
                               broadcast certified tx + FC ───────────────────────────────▶ every node:
                                                                                            verify FC quorum,
                                                                                            store FC, admit to
                                                                                            mempool, relay,
                                                                                            ratify in consensus
```

Validators can **stall** (liveness) but never reverse or mint (safety): the per-UTXO immutable pin +
`2f+1`/`3f+1` quorum intersection guarantee at most one spender per UTXO is ever certified.

---

## Work breakdown

Suggested PR order: A → B → C → D → E → F → G → H. Each PR is independently testable.

### PR A — BLS crypto + validator signer (`hathor/finality/crypto.py`)
- Add dependency **`py-ecc`** (pure-Python BLS12-381, IETF/ETH2 ciphersuite; clean `uv.lock` story —
  CI checks lockfile consistency). Wrap behind our module so the backend can swap to a native lib
  (`blspy`/`blst`) if benchmarks demand — `py_ecc` pairings are slow (perf risk for sub-second target).
  Measured: native `blst` is ~400–1400× faster (verify ≈ 0.6 ms vs ≈ 240 ms), making crypto a
  non-bottleneck and the `py_ecc → blst` swap the recommended production change. See
  [`bls-benchmark.md`](bls-benchmark.md).
- Use the **proof-of-possession** ciphersuite (`G2ProofOfPossession`) + `FastAggregateVerify` (all
  validators sign the same message → one multi-pairing check). PoP defeats rogue-key attacks.
- Functions: `bls_keygen/sk_to_pk/pop_prove/pop_verify/sign/verify/aggregate/fast_aggregate_verify`.
- Classes: `FinalityValidatorSigner` (mirrors `PoaSigner`), `FinalityValidatorSignerFile` (pydantic,
  mirrors `PoaSignerFile`; validates `pk==SkToPk(sk)` and PoP).
- **Canonical pin-message:** `get_pin_message(tx_id) = sha256(b'hathor-fc-pin-v1' || committee_hash ||
  tx_id)`. Commits to `tx_id` only — sound because an honest validator pins *every* input before
  signing (enforce atomically in PR C).

### PR B — Committee settings + feature flag
- New `hathor/finality/finality_settings.py`: `FinalityValidatorSettings(public_key, pop, weight)`,
  `FinalitySettings(enabled, validators[])` with cached `total_weight W`, `f=(W-1)//3`,
  `quorum_threshold=2f+1`, `committee_index` (pubkey→bitmap position), per-position `weights`,
  `reaches_quorum(bitmap)` (weight-summed, **not** count), `calculate_committee_hash()`. Validate every
  PoP at load. Mirror `PoaSettings`.
- `hathor/conf/settings.py`: add `FINALITY: FinalitySettings` and hard flag `ENABLE_TWO_TIER_FINALITY`.
- `hathor/feature_activation/feature.py`: append `Feature.TWO_TIER_FINALITY`; add
  `two_tier_finality: bool` to the `Features` dataclass (`hathor/feature_activation/utils.py`).
- Mix `FINALITY.calculate_committee_hash()` into the peer-hello hash (mirror
  `PoaSettings._calculate_peer_hello_hash`) so mismatched-committee peers don't connect.

### PR C — Pin index + validator service (validator-only, committee gossip + certification)
- New `hathor/indexes/finality_pin_index.py` (+ rocksdb impl): UTXO `(tx_id,index) → pinned spender
  tx_id`. API `get_pin`, `try_pin` (pin iff unpinned or same spender; False on conflict),
  `unpin_resolved`. CF `finality-pin`. **Authoritative state, not a rebuildable cache:**
  `still_needs_initialization()→False`, `init_loop_step` no-op, `force_clear` guarded so reindex /
  `--reset-indexes` cannot wipe pins (accidental wipe lets a validator equivocate — highest severity).
  Register in `manager.py`; created only on validator nodes.
- New `hathor/finality/validator_service.py`. On receiving a pending tx (from a client submission or a
  committee-peer flood), apply the **voting rule**:
  1. `Feature.TWO_TIER_FINALITY` active; 2. finality-eligible `Transaction` (UTXO, non-nano),
  structurally valid; 3. inputs known & unspent — reuse `is_double_spending()==False` and
  `not is_spending_voided_tx()`; 4. no input already pinned to a different tx (`get_pin`);
  5. **FC-chaining:** if an input's source tx is not yet hard-settled, require `fc_store.has_fc(source)`
  else **defer** (retry when that FC arrives).
  On success: `try_pin` **all** inputs atomically (abort + don't sign on any conflict), then
  `signer.sign_pin(...)` → `Vote`. **Committee behavior:** flood the pending tx (if peer lacks it) and
  the new `VOTE` to committee-overlay peers; accumulate incoming votes per tx in the pending pool; the
  first time accumulated weight `≥ 2f+1`, assemble the FC and broadcast the certified tx + FC to the
  whole network (dedupe so only one certified broadcast per tx). Idempotent; all on the reactor thread.

### PR D — Vote/FC objects, p2p messages, committee overlay, FC index
- `hathor/finality/fc.py`: `Vote(tx_id, validator_id, signature)` and
  `FinalityCertificate(tx_id, bitmap, agg_signature)` with `__bytes__`/`from_bytes` and
  `verify(settings, pin_message)` = `reaches_quorum(bitmap)` + `fast_aggregate_verify`.
- `hathor/p2p/messages.py` + `states/ready.py` (gated by new `CAPABILITY_FINALITY`):
  - `SUBMIT_FINALITY_TX` — any node → a validator: carries the full pending tx.
  - `FINALITY_VOTE` — validator ↔ validator flood: a `Vote` (+ the tx if the peer lacks it).
  - certified **tx + FC** relay to the whole network: extend the existing tx-relay/`DATA` push to carry
    the FC bytes (or send the FC immediately alongside the tx).
  Handlers validate hex/length defensively and **verify each vote** (`bls_verify`) before use.
- **Committee overlay / membership proof:** a validator peer proves committee membership at handshake
  (sign the peer-hello challenge with its committee BLS key, verifiable against `FinalitySettings`).
  Validators flood `FINALITY_VOTE`/pending-tx **only to proven-validator peers**; non-validators only
  ever receive the final certified tx via normal network relay. Recommend validators be configured with
  each other's entrypoints to keep the overlay well-connected.
- New **FC index** `hathor/indexes/finality_certificate_index.py` (+ rocksdb + memory): `tx_id →
  FC bytes`; `add_certificate/has_certificate/get_certificate`. Authoritative-not-rebuildable like the
  pin index. Register in `manager.py`; exposed as `storage.indexes.finality_certificate`. The block
  rule needs only `has_certificate(tx_id)` (O(1)).

### PR E — Pending-FC pool, submitter, certified-only mempool gate
- New `hathor/finality/pending_pool.py`: `PendingFinalityPool` keyed by `tx_id → (tx, accumulated
  votes → bitmap)`. In-memory for v1 (pre-final, re-collectable after restart). API: `add(tx)`,
  `add_vote(vote)`, `is_ready(tx_id)`, `assemble_fc(tx_id)`, `pop(tx_id)`. Used by the validator
  service (accumulation) and by submitters (await).
- New `hathor/finality/submitter.py` (any node): for a finality-eligible tx without an FC, place it in
  the pending pool and `SUBMIT_FINALITY_TX` to **one random** `CAPABILITY_FINALITY` validator peer
  (configurable to N>1); await the certified tx from the network.
- **Certified-only mempool gate (every node, independent)** in
  `hathor/vertex_handler/vertex_handler.py` (`on_new_mempool_transaction` / `on_new_relayed_vertex`) and
  the sync-v2 mempool path: for a finality-eligible tx with the feature active —
  - without a valid quorum FC → route to the pending-FC pool (submitter forwards to a validator); do
    **not** add to mempool; do **not** relay.
  - with an FC → **independently** run `FinalityCertificate.verify(...)`; on success store the FC in the
    FC index, admit to the mempool, relay tx+FC onward; on failure drop.
  - blocks, genesis, feature-inactive, and nano txs (out of v1 scope) follow the existing path.
- This gate is the single funnel guaranteeing the mempool only ever holds FC-backed txs, whether a tx
  becomes certified locally (validator) or arrives already certified (everyone else).

### PR F — Ratification block-validity rule (consensus)
- In `_score_block_dfs`, at the `mark_as_best_chain` branch (just before `meta.first_block =
  block.hash`), if `_fc_enabled_for(block)` call `_check_ratifies_no_certified_conflict(tx)`: for each
  input, scan `spent_tx_meta.spent_outputs[index]` siblings; if any sibling `t' != tx` has
  `fc_index.has_certificate(t')`, the block confirms a tx conflicting with a certified one → **invalid**.
  (Gate on FC existence, not `first_block` — a certified tx need not be block-confirmed.)
- **Surface invalidity by voiding the block** (reuse the existing non-winner `mark_as_voided` path), not
  crashing: the offending block becomes a voided side block; the certified tx + descendants stay valid;
  composes with reorg handling for free. Avoid `crash_and_exit`.
- `_fc_enabled_for(block)` mirrors `_should_execute_nano` (gate on the block parent's `Features`).
- **Late-FC reconciliation:** the certified-only mempool means a node holding a certified tx already has
  its FC, so the common case is covered. Residual: a block references a certified tx the node hasn't
  seen → fetch tx+FC; if an FC later contradicts an already-best-chain block, trigger a voiding
  re-evaluation. Bound: the fast tier precedes PoW by construction.

### PR G — Block FC-root commitment (advisory in v1)
- New block header `FCRootHeader` (`VertexHeaderId.FC_ROOT_HEADER = b'\x14'`): 32-byte merkle root.
  Files mirror `FeeHeader` (`headers/fc_root_header.py`, `vertex_parser/_fc_root_header.py`, register in
  `_headers.py` + `get_supported_headers` gated on `ENABLE_TWO_TIER_FINALITY`). Auto-committed by PoW;
  works for `Block`/`MergeMinedBlock`/`PoaBlock`.
- Root = merkle of `sorted(tx.hash for tx in block.iter_transactions_in_this_block() if
  fc_index.has_certificate(tx.hash))`. **Advisory only in v1** (verify well-formedness, not value):
  binding security comes from PR F, which needs the FC known only *locally*. Binding root is a v2 item.

### PR H — Pin housekeeping on settlement (light)
- When a certified tx hard-settles (`first_block` set), emit a settlement signal (collect on the
  consensus context, drain in `Consensus.unsafe_update`, publish `HathorEvents.TX_SETTLED` with consumed
  outpoints). Validator service prunes now-moot pins via `finality_pin_index.unpin_resolved(...)`.
  Safety doesn't depend on this; it's housekeeping and the hook for future wedge-recovery/epoch-unlock.

### Wiring (spans PRs)
- `hathor_cli/run_node_args.py`: add `--finality-signer-file`.
- `hathor_cli/builder.py` + `hathor/builder/builder.py`: build the pending pool + FC index + submitter on
  all nodes; on validators (signer file + `FINALITY.enabled`) also load `FinalityValidatorSignerFile`,
  build `FinalityValidatorService`, register the pin index, enable the committee overlay. Mirror PoA
  wiring (`set_poa_signer`, `_get_or_create_poa_block_producer`).
- New package `hathor/finality/` (`crypto.py`, `finality_settings.py`, `validator_service.py`, `fc.py`,
  `pending_pool.py`, `submitter.py`).

---

## Critical files
- `hathor/vertex_handler/vertex_handler.py` + `hathor/p2p/sync_v2/` — certified-only mempool gate (PR E)
- `hathor/finality/` (new package) — crypto, settings, validator service, FC objects, pending pool, submitter
- `hathor/consensus/block_consensus.py` — ratification rule + settlement signal (PR F, H)
- `hathor/indexes/{manager.py, finality_pin_index.py, finality_certificate_index.py}` (+ rocksdb/memory)
- `hathor/p2p/{messages.py, states/ready.py}` — SUBMIT_FINALITY_TX / FINALITY_VOTE / tx+FC relay + overlay
- `hathor/feature_activation/{feature.py, utils.py}` + `hathor/conf/settings.py` — flag + gating
- `hathor/transaction/headers/{types.py, fc_root_header.py}` + `vertex_parser/_headers.py` — FC root header
- `hathor_cli/{run_node_args.py, builder.py}` + `hathor/builder/builder.py` — wiring
- `pyproject.toml` / `uv.lock` — `py-ecc`

## Reuse (don't reinvent)
- `PoaSigner`/`PoaSignerFile` → BLS signer; `PoaSettings`/`_calculate_peer_hello_hash` → committee
  settings + overlay membership proof; `PoaBlockProducer` lifecycle → validator service.
- `Transaction.is_double_spending` / `is_spending_voided_tx` / `TransactionMetadata.spent_outputs`
  / `get_output_spent_by` → voting rule + ratification conflict scan.
- `BaseIndex` + `rocksdb_utxo_index.py` → pin/FC indexes; `Features.from_vertex` → consensus gating;
  `iter_transactions_in_this_block` → FC-root set; `iter_ready_connections()` → committee/network flood.

---

## Verification

Unit tests (mirror `tests/consensus/`, `tests/p2p/`, `tests/tx/`):
- **Crypto:** sign/aggregate/`fast_aggregate_verify` round-trip; PoP accept/reject; weight-based
  `reaches_quorum` boundary at exactly `2f+1`; bitmap↔committee-index mapping.
- **Voting rule / pin:** honest spender → vote; equivocation split across validator halves → at most one
  reaches quorum, neither when split evenly (wedge); pin immutable across restart; FC-chaining defers a
  child until parent FC present.
- **Quorum safety (theorem):** two conflicting txs can never both assemble an FC.
- **Pending pool / mempool gate:** an un-certified tx stays in the pending pool, absent from the mempool,
  not relayed; submitter forwards to a random validator; on reaching quorum the certified tx is broadcast
  and admitted everywhere; a tx with a forged/insufficient FC is rejected by independent verification.
- **Committee overlay:** votes flood only between proven-validator peers; non-validators receive only the
  certified result; the first validator to reach quorum certifies and others dedupe.
- **Ratification rule:** certify `t1(x→Bob)`, then a block confirming conflicting `t2(x→Carol)` → block
  voided, `t1` + descendants valid; reorg re-runs the guard.
- **Serialization:** Vote/FC/`FCRootHeader` byte round-trips; vote/FC fit one p2p line.

Integration (mirror `tests/simulation/` and existing PoA multi-node tests):
- Simulated committee (n=4, f=1) + a submitter + a plain relay node: submitter forwards to one random
  validator; validators gossip to quorum; assert sub-second soft finality (sim time); the relay node
  only ever sees the tx once certified; a PoW block then settles it.
- Double-spend across validator halves → no FC; tx never leaves any pending pool.

Manual run: nodes started with `--finality-signer-file` on a local/testnet config with `FINALITY.enabled`
+ feature activation; submit a tx; confirm it sits in the pending pool, is forwarded to a validator,
returns certified, appears in the mempool + relays with its FC
(`storage.indexes.finality_certificate`); mine a conflicting block and confirm it is voided.

Quality gates: `make tests` (or `uv run pytest`), `mypy`, lint, `uv.lock` CI consistency check.

---

## Implementation progress

- **PR A — DONE** (`feat(finality): BLS crypto and validator signer [part 1]`): `hathor/finality/crypto.py`,
  `py-ecc` dependency, 13 tests.
- **PR B — DONE** (`feat(finality): committee settings and feature flag [part 2]`):
  `hathor/finality/finality_settings.py`, `FINALITY`/`ENABLE_TWO_TIER_FINALITY` settings,
  `Feature.TWO_TIER_FINALITY`, `Features.two_tier_finality`, peer-hello committee hash, 10 tests.
- **PR D — IN PROGRESS**: data + storage layers done.
  - `feat(finality): vote and finality certificate value objects [part 3]`: `hathor/finality/fc.py`
    (`Vote`, `FinalityCertificate`), 12 tests.
  - `feat(finality): authoritative pin and certificate stores [part 4]`: `hathor/finality/stores.py`
    (pin store + certificate store, memory + RocksDB), wired into `RocksDBIndexesManager` as
    `finality_pin`/`finality_certificate` (created only when `ENABLE_TWO_TIER_FINALITY`, excluded from
    `iter_all_indexes()`), 8 tests incl. a RocksDB reopen/persistence test.
  - **Remaining for PR D**: p2p messages (`SUBMIT_FINALITY_TX`, `FINALITY_VOTE`), `ReadyState`
    handlers gated by `CAPABILITY_FINALITY`, and the committee-overlay membership proof at handshake.

### Final status — v1 fast path complete and working
Done and committed (8 commits), all tests green, no regressions:
- **A** crypto, **B** settings/feature flag, **D(data)** FC/Vote objects, **D(storage)** pin/cert stores.
- **C/E** `feat(finality): validator service and pending pool [part 5]` — `FinalityService` (voting rule,
  atomic pinning, vote gossip, certify-at-quorum, independent cert verification) + `PendingFinalityPool`.
- **F** `feat(finality): ratification block-validity rule [part 6]` — voids a block that confirms a tx
  conflicting with a certified one.
- **D(p2p)/E(gate)/wiring** `feat(finality): p2p transport, certified-only mempool gate, node wiring
  [part 7]` — `SUBMIT_FINALITY_TX`/`FINALITY_VOTE`/`FINALITY_CERTIFICATE` + `CAPABILITY_FINALITY`,
  `P2PFinalityTransport`, the `VertexHandler` divert gate, `--finality-signer-file`, and `FinalityService`
  construction in both `Builder` and `CliBuilder`.
- **H** `feat(finality): release validator pins on settlement [part 8]`.

**Simplifications taken in v1 (documented):**
- The "committee overlay" is the set of `CAPABILITY_FINALITY` peers; vote authenticity rests on BLS
  verification against the committee, not peer identity (a non-validator can neither forge a vote nor
  reach quorum). The handshake committee-membership *proof* is deferred (DoS/privacy hardening only).
- Certified transactions propagate via the `FINALITY_CERTIFICATE` gossip path; sync-v2 FC transport for
  *historical* txs is not needed in v1 (settled conflicts are resolved by consensus anyway).

**Deferred — PR G (advisory FC-root block header):** not implemented. It is explicitly advisory (not
consensus-binding) and only benefits light clients; the binding security comes entirely from PR F.
Implementing it would add a new header type to the hot vertex-serialization path plus a block-template
hook to attach the root — meaningful surface/regression risk for no v1 security value. Recommended as a
follow-up when light-client header verification is prioritized.

### Confirmed storage-integration decision (resolves the "non-rebuildable index" trap)
`IndexesManager._manually_initialize` calls `force_clear()` on every index selected for rebuild
*before* `still_needs_initialization` is consulted, and selection happens whenever an index's
`index_last_started_at` differs from the storage's `last_started_at` (reindex, `--reset-indexes`,
version bump, or crash-during-init). The validator **pin store** (authoritative anti-equivocation
state) and the **FC store** must never be wiped. Therefore implement both as **dedicated persistent
stores** (own RocksDB column family via `RocksDBIndexUtils`, plus a memory variant for tests),
constructed by the indexes managers and exposed as `indexes.finality_pin` / `indexes.finality_certificate`,
but **excluded from `iter_all_indexes()`** so they are never force-cleared. The CF is created in the
store constructor, so exclusion from the iterator is safe. (`iter_all_indexes` callers:
`manager.py` init/clear/init_start loops and `transaction_storage.py:922`.)

## Out of scope (explicitly deferred)
PoS staking & economic slashing; fraud-proof generation & on-chain equivocation evidence; epoch
governance/rotation & on-chain committee records; epoch-boundary unlock; PoW tie-break of uncertified
wedged UTXOs (v1 leaves them frozen — self-harm only); multi-owner griefing mitigation; Nano-Contract
total-order (BFT) path; binding (consensus-critical) FC-root commitment; light-client header-only
verification; validator fee/incentive & anti-spam economics.
