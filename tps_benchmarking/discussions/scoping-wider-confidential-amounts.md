# Scoping — can shielded confidential amounts be wider than 64 bits?

> **Investigation requested:** widen the amount type so the range proof can use >64 bits (the original ask
> was an 82-bit default). **Bottom line: don't.** **64 bits is the correct minimum** — it is the smallest
> width that covers 100% of valid Hathor amounts. Going wider is (a) unnecessary, (b) infeasible with this
> crypto stack, and (c) would *violate* consensus. Going narrower (63) is **too tight** — it would reject the
> legal maximum output. So 64 is both the floor and the recommended default.

---

## 1. The decisive fact: Hathor caps every amount at 2^63

`hathor/transaction/base_transaction.py:54` — `MAX_OUTPUT_VALUE = 2**63` (≈9.22e18). Enforced for every
transparent output: `if value <= 0 or value > MAX_OUTPUT_VALUE: raise InvalidOutputValue`
(`base_transaction.py:1040`). This is a **consensus cap on all output values, for all tokens** — no valid
output can exceed 2^63.

**Important:** `MAX_OUTPUT_VALUE = 2^63` is **inclusive** (`value > MAX_OUTPUT_VALUE` raises ⇒ `value == 2^63`
is legal), and `2^63` has **bit-length 64** — i.e. the legal *maximum* value requires **64 bits** to
represent (it is one above the signed-i64 max `2^63−1`, encoded via Hathor's value-negation trick). So the
legal value set is `[1, 2^63]`.

Consequences for the range-proof bit-width (the range proof proves the committed amount ∈ `[1, 2^bits)`):

- A **63-bit** proof covers `[1, 2^63)` — which **excludes** the legal maximum `2^63`. **Too tight**: it would
  reject a max-value output. (So 63 is *not* the consensus-matching width — that was a miscalculation.)
- A **64-bit** proof covers `[1, 2^64)` ⊇ `[1, 2^63]` → the **minimum** width that covers **100%** of legal
  amounts. Its only looseness: it also admits hidden values in `(2^63, 2^64)`, which are illegal; closing that
  exactly is impossible with a single power-of-2 range proof (`2^63` inclusive is not a `[0, 2^N)` boundary)
  and would need extra constraints — inherent and minor.
- Anything **>64** (e.g. 82) proves a strictly looser bound than consensus already enforces → it adds **no**
  capability and **no** security. It only makes proofs bigger and slower.

## 2. Why >64 is not just useless but *wrong* for shielded outputs

For a **shielded** output the value is hidden, so there is **no** `MAX_OUTPUT_VALUE` check — the **range
proof is the sole thing bounding the value** (`TransactionVerifier.verify_range_proofs`,
`transaction_verifier.py:792`). Therefore the bit-width directly defines the consensus value bound for
confidential outputs:

- At **64 bits**, a shielded output can provably hide a value in `[1, 2^64)` — i.e. up to one bit *above*
  the transparent `MAX_OUTPUT_VALUE = 2^63`. A minor looseness already present in the design choice.
- At **82 bits** (were it possible), a shielded output could hide a value up to `2^82 − 1` — **~500,000×
  the maximum legal supply**. That breaks the invariant that every amount ≤ 2^63 and would let confidential
  outputs encode values that are illegal the moment they are unshielded. **82-bit range proofs would be a
  consensus bug, not a feature.**

There is **no tighter clean option** than 64: a 63-bit proof would reject the legal max `2^63`, and `2^63`
inclusive is not a power-of-2 range boundary. So **64 is the correct minimum**, full stop. (Upstream chose
**40**, which is the opposite problem — it silently caps confidential amounts at `2^40 ≈ 1.1e12`, so any legal
output above ~1.1e12 — up to the legal max 9.2e18 — **cannot be represented as a shielded output at all**.
That is arguably an upstream limitation in its own right; our 64-bit default fixes it.)

## 3. Could the Borromean proof itself be extended past 64 bits? (yes — but only by forking the audited C library)

**The 64-bit cap is an implementation/type limit, not a Borromean design limit.** The crypto is
**secp256k1-zkp 0.11** (`hathor-ct-crypto/Cargo.toml:7`), wrapping libsecp256k1-zkp's Borromean range proof.
Reading the vendored C source
(`secp256k1-zkp-sys-0.10.1/depend/secp256k1/src/modules/rangeproof/rangeproof_impl.h`), the ring construction
is generic — the limit comes from the value type and 64-bit arithmetic around it, not from the ring algebra:

```c
// secp256k1_range_proveparams(..., uint64_t value)            // L113-114: value is uint64_t (the hard limit)
*mantissa = *v ? 64 - ..._clz64_var(*v) : 1;                   // L162: mantissa from a uint64 -> <= 64
*rings = (*mantissa + 1) >> 1;                                 // L168-171: ring count is DYNAMIC (scales with
for (...) rsizes[i] = (...) ? 4 : 2;                           //          mantissa) -- no hardcoded 64 here
VERIFY_CHECK((*v & ~(UINT64_MAX>>(64-*mantissa))) == 0);       // L175: UINT64_MAX masks -> 64-bit arithmetic
// (verifier assumes the proven range is within [0, 2^64) -- L139 comment)
```

So Borromean *could* prove more digits (the `rings`/`rsizes`/`npub` arrays grow with `mantissa`). What pins it
to 64 is: (1) the **`uint64_t value`** parameter — in `rangeproof_impl.h` **and** the public
`include/secp256k1_rangeproof.h` `secp256k1_rangeproof_sign(..., uint64_t value, ...)`; (2) 64-bit ops
(`clz64_var`, `UINT64_MAX` masks); (3) the **verifier's `[0, 2^64)` assumption**. The Pedersen commitment side
already commits to a ~256-bit scalar, so it is **not** the blocker.

**To expand it** you would fork libsecp256k1-zkp: widen the value type (`uint64_t → __int128`/byte-array)
across `rangeproof_impl.h` / `borromean_impl.h` / the public header, replace the 64-bit ops, lift the
verifier's `2^64` assumption, then patch the `secp256k1-zkp-sys` C bindings + the `rust-secp256k1-zkp` wrapper,
and **re-audit**. That means modifying a security- and consensus-critical audited library and diverging from
upstream — high effort, ongoing maintenance/audit burden.

**Cheaper alternative already in the API:** the `exp` parameter
(`secp256k1_rangeproof_sign(..., int exp, ...)`) proves `value × 10^exp` with a ≤64-bit mantissa — extending
representable *magnitude* at the cost of low-digit precision. This is how **Liquid** represents larger nominal
amounts while keeping ≤8 decimals of precision. It does **not** give wider exact-integer ranges.

Empirically (CP-8): `bits=40 → 3213 B`, `bits=64 → 5070 B`, **`bits=82 → ERROR`, `bits=96 → ERROR`**
("failed to generate range proof"). The crate also exposes **no Bulletproof module** (bulletproofs were
experimental and never merged into maintained libsecp256k1-zkp) — so there is no *in-stack* path to >64-bit
ranges without the fork above.

## 4. What "widening the amount type" would actually require (and cost)

To support confidential amounts above 2^63 you would need **all** of:

1. **Consensus change:** raise `MAX_OUTPUT_VALUE` beyond 2^63 — a hard fork affecting **every** transaction,
   plus the on-wire value encoding (currently i64 / ≤8 bytes) for transparent outputs.
2. **A >64-bit range proof:** either fork libsecp256k1-zkp to widen the Borromean value type (§3 — modifying
   audited consensus crypto), adopt Bulletproofs (not in the crate; a different proof system + security
   review), or multi-limb composition (non-standard; the balance/audit equations would need rework).
3. **Wider amount type end-to-end:** `u64 → u128` (or bignum) across the FFI, commitment creation, rewind,
   balance, surjection, and the Python/serialization layers.
4. **Re-audit** of the supply-conservation and balance proofs under the new value domain.

This is a multi-quarter, network-wide cryptographic re-architecture, undertaken to represent amounts that
**Hathor consensus forbids**. There is no benchmark or product benefit.

## 5. Recommendation

- **Keep the range-proof bit-width at 64** (CP-8 default). It is the **minimum** width that covers the full
  legal amount range `[1, 2^63]` (because the inclusive max `2^63` needs 64 bits) **and** the **maximum** the
  stack supports — so it is the single correct value. Do **not** drop to 63 (rejects the legal max). The
  toggle (`HATHOR_RANGE_PROOF_BITS`, 1..=64) stays for benchmark sweeps (40/64) to chart proof-size/verify-cost
  vs width — but 40 is not consensus-valid for large amounts (see §2), so it's a benchmarking axis, not a
  production option.
- **Do not pursue >64-bit amounts / amount-type widening.** It is infeasible with secp256k1-zkp, unnecessary
  given `MAX_OUTPUT_VALUE = 2^63`, and at 82 bits would be actively consensus-violating.
- The "82" target appears to be a misreading of the parameter: range-proof *bits* is the proven-range
  **ceiling** (bounded by the amount type and consensus), not a free security/strength dial. For Hathor there
  is exactly **one correct value: 64**.

*(For the benchmark we benefit from the toggle regardless: range-proof size and verify cost vs bit-width is a
clean sweep axis — see CP-10.)*
