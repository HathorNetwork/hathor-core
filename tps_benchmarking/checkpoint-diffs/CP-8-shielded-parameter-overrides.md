# Checkpoint CP‑8 — Shielded parameter overrides (range‑proof bits + per‑tx caps)

- **Snapshot A:** end of CP‑7 — shielded base branch, native crypto compiled, the balance‑reconciliation
  fix; shielded txs build + verify at the upstream 40‑bit range proof and the upstream 32‑output cap.
- **Snapshot B:** two shielded **parameters are now configurable**, with raised defaults:
  (1) the range‑proof bit‑width (default **64**, env‑toggleable), and (2) the per‑tx shielded‑output cap
  (default 32, overridable up to **255**). Both validated end‑to‑end.
- **Status:** PASS ✓ — proofs are 5070 B at the new 64‑bit default and txs verify; a 40‑output tx is
  rejected by default and accepted with the cap lifted; the bit‑width toggles via env (40→3213 B, 64→5070 B).
- **Files changed:** 2 ⚠️ **non‑engine** files — `hathor-ct-crypto/src/rangeproof.rs` (+ rebuild),
  `hathorlib/hathorlib/transaction/shielded_tx_output.py`. (CP‑renumber: the workload sources move to CP‑9,
  measurement/flags to CP‑10.)

---

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║  ⚠️  MODIFIES THE RUST CRYPTO CRATE AND HATHORLIB — NOT JUST THE BENCHMARK ENGINE  ⚠️  ║
║                                                                                        ║
║  hathor-ct-crypto/src/rangeproof.rs               (native crate; requires rebuild)     ║
║  hathorlib/hathorlib/transaction/shielded_tx_output.py   (shared policy constants)     ║
║                                                                                        ║
║  These are deliberate deviations from upstream feat/shielded-outputs, carried on our   ║
║  branch tool/tps-bench-shielded. Re-apply if the branch is updated upstream.           ║
║  The boxed CP-7 core patch (vertex_exporter.py) is the other core change.              ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 1. Summary

Two knobs that matter for shielded benchmarking are now configurable rather than hard‑coded:

1. **Range‑proof bit‑width** — drives proof size (≈ S1 deserialize, S5 storage, disk, RSS) and verify cost.
   Default raised from 40 to **64**; toggle per run via `HATHOR_RANGE_PROOF_BITS`.
2. **Max shielded outputs per tx** — drives how "fat" a single shielded tx can get. Default stays 32 but is
   now overridable up to the hard ceiling **255** via `HATHOR_MAX_SHIELDED_OUTPUTS`.

Plus the dependent `MAX_RANGE_PROOF_SIZE` cap is raised/made‑configurable so the larger proofs aren't
rejected by the deserializer.

## 2. ⚠️ The 82‑bit request → 64‑bit reality (important)

The request was an **82‑bit** default. **82 bits is not achievable** and was empirically rejected:

```text
bits= 40: 3213B verify=True
bits= 64: 5070B verify=True
bits= 82: ERROR: range proof error: failed to generate range proof
bits= 96: ERROR: range proof error: failed to generate range proof
```

The committed `amount` is a **`u64`**, and secp256k1‑zkp's Borromean range proof caps `min_bits` at **64**
(you cannot prove an 82‑bit range for a 64‑bit value). Going above 64 would require a **wider amount type**
end‑to‑end (commitments, serialization, consensus) — far outside a parameter tweak. The default was therefore
set to **64** (the true maximum, and the widest range > 40 that the request was reaching for). The knob is
toggleable across `1..=64`; values > 64 fail loudly at proof creation. **Open question for the user: confirm
64, or is there an intent to widen the amount type?**

## 3. What changed, and the toggle surface

| Parameter | Where | Default (this branch) | Upstream | Toggle | Ceiling |
|---|---|---|---|---|---|
| Range‑proof bits | `rangeproof.rs::RANGE_PROOF_BITS` | **64** | 40 | `HATHOR_RANGE_PROOF_BITS` (runtime, per proof) | 64 (u64 / Borromean) |
| Max shielded outputs/tx | `shielded_tx_output.py::MAX_SHIELDED_OUTPUTS` | 32 | 32 | `HATHOR_MAX_SHIELDED_OUTPUTS` (`int` or `max`) | 255 (1‑byte count) |
| Max range‑proof size | `shielded_tx_output.py::MAX_RANGE_PROOF_SIZE` | **8192** | 3328 | `HATHOR_MAX_RANGE_PROOF_SIZE` | 65535 (2‑byte len) |

Notes:
- **Range bits is read at *creation* time** (a Borromean proof is self‑describing, so verify needs no
  bit‑width). The env is read on every `create_range_proof`, so a benchmark can sweep widths between batches
  in one process. Creation happens in untimed setup, so the env read is free.
- **Caps are resolved at *import* time** (they're module constants imported by the verifier and both
  deserializers — `hathor` and `hathorlib`). The benchmark harness must set these env vars **before**
  importing hathor/hathorlib. `max`/`lift`/`unlimited` → the hard ceiling; integers are clamped to `[1, ceiling]`.
- **No separate shielded‑INPUT cap exists.** Shielded inputs are ordinary `TxInput`s, bounded only by the
  normal per‑tx input‑count byte (also 255). So "lift the shielded‑input limit" == the standard input limit;
  this CP governs **outputs**. Called out in the code comment too.

## 4. Verified

```text
# (a) bit-width toggle + the 64-bit cap (HATHOR_RANGE_PROOF_BITS)
default (64): 5070B verify=True
bits= 40: 3213B verify=True     bits= 64: 5070B verify=True
bits= 82: ERROR (failed to generate range proof)   bits= 96: ERROR

# (b) shielded tx still builds + verifies at the 64-bit default
(B) tx_full : shielded_outputs=2 accepted=True serialized=10772B
(B) tx_amt  : shielded_outputs=2 accepted=True serialized=10569B   # was ~6.8KB @40-bit

# (c) MAX_SHIELDED_OUTPUTS override resolves correctly
default=32 | env=100 -> 100 | env=max -> 255 | env=999 -> 255 (clamped)

# (d) the cap override works END-TO-END (40 shielded outputs in one tx)
default (cap 32): accepted=False  err="too many shielded outputs: 40 exceeds maximum 32"
env=max (cap 255): accepted=True
```

Run them:
```bash
cd /home/lyzah/hathor-projects/p6_tps_benchmark/hathor-core
# rebuild after any rangeproof.rs change:
poetry run maturin develop --release --manifest-path hathor-ct-crypto/Cargo.toml --features python
# bit-width + sizes:
PYTHONPATH=$PWD HATHOR_RANGE_PROOF_BITS=40 poetry run python tps_benchmarking/benchmarks/engine/spikes/spike_cp7_shielded.py
# cap override: set HATHOR_MAX_SHIELDED_OUTPUTS=max before the import.
```

## 5. The diffs (A → B)

### 5a. ⚠️ `hathor-ct-crypto/src/rangeproof.rs` (+ rebuild)

```diff
+use std::env;
 use std::ops::Range;
 ...
-/// 40 bits covers values up to 2^40 ...
-pub const RANGE_PROOF_BITS: usize = 40;
+/// BENCHMARK BRANCH: the default is **64** (was 40). 64 bits is the FULL range of a
+/// u64 amount and the largest the proof system supports. (82 was requested but fails:
+/// secp256k1-zkp Borromean caps min_bits at 64.) TOGGLE: HATHOR_RANGE_PROOF_BITS (1..=64).
+pub const RANGE_PROOF_BITS: usize = 64;
+
+fn configured_range_proof_bits() -> u8 {
+    match env::var("HATHOR_RANGE_PROOF_BITS") {
+        Ok(v) => v.trim().parse::<u8>().unwrap_or(RANGE_PROOF_BITS as u8),
+        Err(_) => RANGE_PROOF_BITS as u8,
+    }
+}
@@ create_range_proof(...) RangeProof::new(...)
-        RANGE_PROOF_BITS as u8, // min_bits: fixed to prevent size side-channel
+        configured_range_proof_bits(), // min_bits: default RANGE_PROOF_BITS (64), env-toggleable
```

### 5b. ⚠️ `hathorlib/hathorlib/transaction/shielded_tx_output.py`

```diff
+import os
 ...
+def _env_capped_int(name: str, default: int, *, hard_max: int) -> int:
+    """Override a shielded-policy cap from env (int, or 'max'/'lift'); clamp to [1, hard_max]."""
+    raw = os.environ.get(name)
+    if raw is None: return default
+    if raw.strip().lower() in ('max', 'lift', 'unlimited'): return hard_max
+    return min(hard_max, max(1, int(raw)))
 ...
-MAX_RANGE_PROOF_SIZE = 3328       # Borromean @ 40-bit: 3213 B + headroom
+# raised to fit the 64-bit default (~5070 B); toggle HATHOR_MAX_RANGE_PROOF_SIZE (ceiling 65535)
+MAX_RANGE_PROOF_SIZE = _env_capped_int('HATHOR_MAX_RANGE_PROOF_SIZE', 8192, hard_max=65535)
 ...
-MAX_SHIELDED_OUTPUTS = 32         # Maximum number of shielded outputs per transaction
+# default 32; override HATHOR_MAX_SHIELDED_OUTPUTS=<int>|max (ceiling 255 = 1-byte count).
+# No separate shielded-INPUT cap: shielded inputs are ordinary TxInputs (also capped at 255).
+MAX_SHIELDED_OUTPUTS = _env_capped_int('HATHOR_MAX_SHIELDED_OUTPUTS', 32, hard_max=255)
```

## 6. Next

- **CP‑9 — shielded workload sources** (was CP‑8): `workload/shielded.py` (`amount-shielded` / `full-shielded`
  TxSources) + `NodeHarness` enabling the feature flag. These env toggles will be surfaced as engine CLI
  flags here (e.g. `--range-proof-bits`, `--max-shielded-outputs`) that simply set the env before harness start.
- **CP‑10 — measure + flags + findings**: S1–S6 on shielded; bit‑width and cap **sweeps** become first‑class
  axes (proof size vs bits; per‑tx cost vs #shielded outputs).
