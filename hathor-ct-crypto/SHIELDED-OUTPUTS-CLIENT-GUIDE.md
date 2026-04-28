# Shielded Outputs: Client Integration Guide

This guide explains how wallets and explorers interact with Hathor's shielded outputs using the `hathor-ct-crypto` library. All three bindings -- Rust (direct), Python (PyO3), and Node.js/TypeScript (NAPI) -- wrap the same Rust implementation.

> **Scope:** This guide covers creating, verifying, recovering, and spending shielded outputs. Transaction assembly (attaching headers, signing, etc.) is covered in the transaction format specification; this guide focuses on the `hathor-ct-crypto` primitives the wallet and explorer need.

---

## Workflow Overview

Shielded outputs attach to regular v1/v2 transactions via a `ShieldedOutputsHeader` -- no new transaction version is needed. A transaction can mix transparent and shielded outputs freely. When a tx spends shielded inputs into *only* transparent outputs (a **full unshield**), it additionally carries an `UnshieldBalanceHeader` with a revealed excess blinding factor (Section 2.4).

**Sender workflow (shielding or partial unshield, at least one shielded output):**

1. Generate blinding factors (Section 2.0)
2. Create shielded outputs (Section 2.1 / 2.2)
3. Compute the balancing blinding factor for the last shielded output (Section 2.3)
4. Attach outputs to the transaction's `ShieldedOutputsHeader`

**Sender workflow (full unshield, shielded inputs only → transparent outputs only):**

1. Compute the excess blinding factor `excess = sum(r_in) − sum(r_out)` (Section 2.4)
2. Attach the scalar to the transaction's `UnshieldBalanceHeader`

**Verifier workflow (full nodes, explorers):**

1. Validate curve points (Section 3.1)
2. Verify range proofs (Section 3.2)
3. Verify surjection proofs for FullShielded outputs (Section 3.3)
4. Verify commitment balance, passing the excess scalar when a `UnshieldBalanceHeader` is present (Section 3.4)

**Recipient workflow:**

1. Rewind the output using your private key (Section 4.1 / 4.2)
2. Cross-check recovered token UID for FullShielded outputs (Section 4.3)
3. Store the recovered blinding factor(s) -- needed to spend the output later

### Cross-Language API Names

The Python/TypeScript bindings use snake_case / camelCase names. Most functions have identical names across bindings, with one exception:

| Operation | Rust (internal) | Python | TypeScript |
|-----------|----------------|--------|------------|
| Create AmountShielded | `create_amount_shielded_output` | `create_amount_shielded_output` | `createAmountShieldedOutput` |
| Create FullShielded | `create_full_shielded_output` | `create_shielded_output_with_both_blindings` | `createShieldedOutputWithBothBlindings` |
| Rewind AmountShielded | `rewind_amount_shielded_output` | `rewind_amount_shielded_output` | `rewindAmountShieldedOutput` |
| Rewind FullShielded | `rewind_full_shielded_output` | `rewind_full_shielded_output` | `rewindFullShieldedOutput` |

**Return field names** also differ slightly:

| Rust field | Python field | TypeScript field |
|------------|-------------|-----------------|
| `value_blinding_factor` | `blinding_factor` | `blindingFactor` |
| `asset_commitment` | `asset_commitment` | `assetCommitment` |
| `asset_blinding_factor` | `asset_blinding_factor` | `assetBlindingFactor` |

---

## 1. Output Types

Hathor offers two privacy tiers for shielded outputs.

### AmountShieldedOutput

Hides the **amount**. The token type remains visible.

| Field | Size | Source | Description |
|-------|------|--------|-------------|
| `commitment` | 33 B | library | Pedersen commitment `C = value * H_token + r * G` |
| `range_proof` | ~675 B | library | Bulletproof proving value is in [1, 2^64) |
| `script` | variable | caller | Locking script (P2PKH, etc.) -- set at the transaction layer |
| `token_data` | 1 B | caller | Token index (same as `TxOutput.token_data`) |
| `ephemeral_pubkey` | 33 B | library | Sender's ephemeral public key for ECDH recovery |

**Use when:** the token type is not sensitive (e.g., HTR transfers).

### FullShieldedOutput

Hides **both** the amount and the token type.

| Field | Size | Source | Description |
|-------|------|--------|-------------|
| `commitment` | 33 B | library | Pedersen commitment `C = value * A + r * G` where `A` is the blinded generator |
| `range_proof` | ~675 B | library | Bulletproof (embeds encrypted token UID + asset blinding in message) |
| `script` | variable | caller | Locking script |
| `asset_commitment` | 33 B | library | Blinded asset tag `A = H_token + r_asset * G` |
| `surjection_proof` | ~130 B | library | Proves the hidden token is one of the input tokens |
| `ephemeral_pubkey` | 33 B | library | Sender's ephemeral public key for ECDH recovery |

**Use when:** the token type is sensitive (e.g., custom tokens, stablecoins).

---

## 2. Creating Shielded Outputs

The high-level `create_*` functions handle the full pipeline: ephemeral keypair generation, ECDH shared secret, nonce derivation, Pedersen commitment, and Bulletproof range proof -- in a single call.

### 2.0 Generating Blinding Factors

Blinding factors must be valid secp256k1 scalars (non-zero, less than the curve order). Always use the library's generator -- raw `os.urandom()` or `rand::random()` may produce invalid scalars.

#### Rust

```rust
use hathor_ct_crypto::ecdh::generate_random_blinding_factor;

let vbf: [u8; 32] = generate_random_blinding_factor(); // value blinding factor
let abf: [u8; 32] = generate_random_blinding_factor(); // asset blinding factor (FullShielded)
```

#### Python

```python
import hathor_ct_crypto as ct

vbf = ct.generate_random_blinding_factor()  # bytes, 32 B
abf = ct.generate_random_blinding_factor()  # bytes, 32 B
```

#### TypeScript

```typescript
import { generateRandomBlindingFactor } from 'hathor-ct-crypto';

const vbf = generateRandomBlindingFactor(); // Buffer, 32 B
const abf = generateRandomBlindingFactor(); // Buffer, 32 B
```

### 2.1 AmountShieldedOutput

#### Rust

```rust
use hathor_ct_crypto::ecdh::{create_amount_shielded_output, generate_random_blinding_factor};

let value: u64 = 5000;
let recipient_pubkey: &[u8; 33] = /* recipient's compressed secp256k1 pubkey */;
let token_uid: [u8; 32] = [0u8; 32]; // HTR = all zeros
let vbf: [u8; 32] = generate_random_blinding_factor();

let output = create_amount_shielded_output(
    value,
    recipient_pubkey,
    &token_uid,
    &vbf,
)?;

// output.ephemeral_pubkey  -- 33 B, store on-chain
// output.commitment        -- 33 B, store on-chain
// output.range_proof       -- ~675 B, store on-chain
// output.value_blinding_factor -- 32 B, keep secret (needed to spend)
```

#### Python

```python
import hathor_ct_crypto as ct

value = 5000
recipient_pubkey = b'\x02...'  # 33-byte compressed pubkey
token_uid = b'\x00' * 32       # HTR
vbf = ct.generate_random_blinding_factor()

output = ct.create_amount_shielded_output(value, recipient_pubkey, token_uid, vbf)

output.ephemeral_pubkey   # bytes, 33 B
output.commitment         # bytes, 33 B
output.range_proof        # bytes, ~675 B
output.blinding_factor    # bytes, 32 B
```

#### TypeScript (Node.js)

```typescript
import {
  createAmountShieldedOutput,
  generateRandomBlindingFactor,
  type CreatedAmountShieldedOutput,
} from 'hathor-ct-crypto';

const value = 5000;
const recipientPubkey: Buffer = /* 33-byte compressed pubkey */;
const tokenUid = Buffer.alloc(32); // HTR
const vbf = generateRandomBlindingFactor();

const output: CreatedAmountShieldedOutput = createAmountShieldedOutput(
  value,
  recipientPubkey,
  tokenUid,
  vbf,
);

output.ephemeralPubkey;  // Buffer, 33 B
output.commitment;       // Buffer, 33 B
output.rangeProof;       // Buffer, ~675 B
output.blindingFactor;   // Buffer, 32 B
```

### 2.2 FullShieldedOutput

> **Note:** The Python/TypeScript bindings expose this as `create_shielded_output_with_both_blindings`. The underlying Rust function is `create_full_shielded_output`. See the cross-language table in the Workflow Overview.

#### Rust

```rust
use hathor_ct_crypto::ecdh::{create_full_shielded_output, generate_random_blinding_factor};

let value: u64 = 7777;
let recipient_pubkey: &[u8; 33] = /* ... */;
let token_uid: [u8; 32] = /* actual token UID, 32 bytes */;
let vbf: [u8; 32] = generate_random_blinding_factor();
let abf: [u8; 32] = generate_random_blinding_factor();

let output = create_full_shielded_output(
    value,
    recipient_pubkey,
    &token_uid,
    &vbf,
    &abf,
)?;

// All AmountShielded fields, plus:
// output.asset_commitment        -- 33 B, store on-chain
// output.asset_blinding_factor   -- 32 B, keep secret
```

#### Python

```python
output = ct.create_shielded_output_with_both_blindings(
    7777,
    recipient_pubkey,
    token_uid,
    vbf,
    abf,
)

output.asset_commitment        # bytes, 33 B
output.asset_blinding_factor   # bytes, 32 B
```

#### TypeScript

```typescript
import { createShieldedOutputWithBothBlindings } from 'hathor-ct-crypto';

const output = createShieldedOutputWithBothBlindings(
  7777,
  recipientPubkey,
  tokenUid,
  vbf,
  abf,
);

output.assetCommitment;        // Buffer | null, 33 B
output.assetBlindingFactor;    // Buffer | null, 32 B
```

### 2.3 Blinding Factor Management

Pedersen commitments are homomorphic: `Commit(a, r1) + Commit(b, r2) = Commit(a+b, r1+r2)`. The network verifies transaction balance by checking that commitment sums match (see Section 3.4). For this to work, the blinding factors must be coordinated: **the sum of input blinding factors must equal the sum of output blinding factors** (per token type).

In practice, assign random blinding factors to all outputs except the last, then compute the last output's blinding factor so the sum balances.

Each entry in the `inputs` and `other_outputs` lists is a triple of `(value, value_blinding_factor, generator_blinding_factor)`:
- **value_blinding_factor** (vbf): the `r` in the Pedersen commitment
- **generator_blinding_factor** (gbf): the asset blinding factor. Use `b'\x00' * 32` (all zeros) for AmountShielded outputs and transparent inputs/outputs; use the actual `abf` for FullShielded outputs.

#### Worked Example

A transaction with 1 transparent input (100 HTR) and 2 AmountShielded outputs (60 + 40 HTR):

```python
import hathor_ct_crypto as ct

# Input: transparent 100 HTR -- vbf and gbf are both zero
input_vbf = b'\x00' * 32
input_gbf = b'\x00' * 32

# Output 1: 60 HTR shielded -- random vbf, gbf is zero (AmountShielded)
out1_vbf = ct.generate_random_blinding_factor()
out1_gbf = b'\x00' * 32

# Output 2: 40 HTR shielded -- compute balancing vbf
last_vbf = ct.compute_balancing_blinding_factor(
    value=40,
    generator_blinding_factor=b'\x00' * 32,  # last output's gbf (zero for AmountShielded)
    inputs=[(100, input_vbf, input_gbf)],
    other_outputs=[(60, out1_vbf, out1_gbf)],
)

# Now create the outputs using these blinding factors
out1 = ct.create_amount_shielded_output(60, recipient_pubkey, token_uid, out1_vbf)
out2 = ct.create_amount_shielded_output(40, recipient_pubkey, token_uid, last_vbf)
```

#### Rust

```rust
use hathor_ct_crypto::balance::compute_balancing_blinding_factor;

let last_vbf = compute_balancing_blinding_factor(
    40,                          // last output value
    &[0u8; 32],                  // last output's gbf (zero for AmountShielded)
    &[(100, input_vbf, [0u8; 32])],   // inputs: (value, vbf, gbf)
    &[(60, out1_vbf, [0u8; 32])],     // other outputs: (value, vbf, gbf)
)?;
```

#### TypeScript

```typescript
import { computeBalancingBlindingFactor } from 'hathor-ct-crypto';

const lastVbf = computeBalancingBlindingFactor(
  40,                                // last output value
  Buffer.alloc(32),                  // last output's gbf (zero for AmountShielded)
  [{ value: 100, valueBlindingFactor: inputVbf, generatorBlindingFactor: Buffer.alloc(32) }],
  [{ value: 60, valueBlindingFactor: out1Vbf, generatorBlindingFactor: Buffer.alloc(32) }],
);
```

### 2.4 Unshielding (Shielded input → Transparent output, no shielded output)

A **full unshield** tx spends one or more shielded inputs into transparent outputs only -- there are no shielded outputs to absorb the residual blinding factor. Section 2.3's trick (put a balancing `vbf` on the last shielded output) does not apply, and the balance equation `sum(C_in) = sum(C_out)` cannot hold because the input side still carries `sum(r_in)*G` that has no counterpart on the transparent-output side.

The sender resolves this by revealing the residual `excess = sum(r_in) − sum(r_out)` as a 32-byte scalar, attached to the transaction's `UnshieldBalanceHeader` (header id `0x13`, 32-byte field, fully covered by the tx sighash). The verifier reconstructs `excess * G` and adds it to the output side so the equation balances (Section 3.4).

**Attaching the header is mutually exclusive with `ShieldedOutputsHeader`**: a tx must carry either one, never both, never neither (for shielded txs). These invariants are enforced at the FFI boundary (see Section 3.4).

#### Privacy note

Revealing `excess` leaks a scalar on `G`:

- With **exactly one shielded input**, `excess = r_in` of that input -- effectively the input's blinding factor is exposed. This is not a privacy regression: the transparent outputs of a full unshield already disclose the spent amount, and the input is being spent, so nothing previously-hidden remains private after the tx exists.
- With **two or more shielded inputs**, only the *sum* of their blinding factors is revealed. Individual blinding factors -- and therefore individual input amounts -- remain confidential. An observer learns the total unshielded amount (from the transparent outputs) but cannot tell how it was split across the inputs.

#### Computing the excess

Use `compute_balancing_blinding_factor` with `value = 0` and an empty "last gbf" -- the function then returns the pure sum `sum(input_vbfs) − sum(other_output_vbfs)`, which is the excess we want. All transparent entries carry `vbf = 0, gbf = 0`; include any transparent fee entries in `other_outputs` so the scalar covers the full output side.

#### Python

```python
import hathor_ct_crypto as ct

# Shielded inputs: the recipient already knows these blinding factors from rewind
# (Section 4.1). For a multi-input unshield, include every shielded input.
shielded_input_entries = [
    (amount_1, r_in_1, b'\x00' * 32),  # AmountShielded: gbf = 0
    (amount_2, r_in_2, b'\x00' * 32),
]

# All transparent entries (outputs + any transparent fee) contribute (value, 0, 0).
transparent_entries = [
    (transparent_out_1_amount, b'\x00' * 32, b'\x00' * 32),
    (fee_amount, b'\x00' * 32, b'\x00' * 32),  # if the tx has a transparent fee
]

excess = ct.compute_balancing_blinding_factor(
    value=0,                          # last "output" has value 0 (placeholder)
    generator_blinding_factor=b'\x00' * 32,
    inputs=shielded_input_entries,
    other_outputs=transparent_entries,
)

# Attach `excess` (32 B) to the tx's UnshieldBalanceHeader.
```

#### Rust

```rust
use hathor_ct_crypto::balance::compute_balancing_blinding_factor;

let excess = compute_balancing_blinding_factor(
    0,                                // last "output" value = 0
    &[0u8; 32],                       // last gbf = 0
    &[
        (amount_1, r_in_1, [0u8; 32]),
        (amount_2, r_in_2, [0u8; 32]),
    ],
    &[
        (transparent_out_1_amount, [0u8; 32], [0u8; 32]),
        (fee_amount, [0u8; 32], [0u8; 32]),
    ],
)?;
```

#### TypeScript

```typescript
import { computeBalancingBlindingFactor } from 'hathor-ct-crypto';

const excess = computeBalancingBlindingFactor(
  0,
  Buffer.alloc(32),
  [
    { value: amount1, valueBlindingFactor: rIn1, generatorBlindingFactor: Buffer.alloc(32) },
    { value: amount2, valueBlindingFactor: rIn2, generatorBlindingFactor: Buffer.alloc(32) },
  ],
  [
    { value: out1Amount, valueBlindingFactor: Buffer.alloc(32), generatorBlindingFactor: Buffer.alloc(32) },
    { value: feeAmount,  valueBlindingFactor: Buffer.alloc(32), generatorBlindingFactor: Buffer.alloc(32) },
  ],
);
```

---

## 3. Verifying Shielded Outputs

Full nodes and explorers verify shielded outputs without knowing the hidden values. Perform these checks in order.

### 3.1 Point Validation

Before any other verification, validate that commitments and generators are valid secp256k1 curve points:

```python
# Python
assert ct.validate_commitment(output.commitment)        # 33 B
assert ct.validate_generator(output.asset_commitment)    # 33 B (FullShielded only)
```

```typescript
// TypeScript
validateCommitment(output.commitment);       // throws on invalid
validateGenerator(output.assetCommitment);   // throws on invalid (FullShielded only)
```

### 3.2 Range Proof Verification

Proves the committed value is in [1, 2^64) -- i.e., no negative or zero amounts.

```rust
// Rust -- returns Range<u64> on success (always 0..2^64 for Hathor), Err on failure
use hathor_ct_crypto::rangeproof::verify_range_proof;

let range = verify_range_proof(&proof, &commitment, &generator)?;
```

```python
# Python -- returns bool
valid: bool = ct.verify_range_proof(proof, commitment, generator)
```

```typescript
// TypeScript -- returns boolean
const valid: boolean = verifyRangeProof(proof, commitment, generator);
```

> The Rust binding returns the proven value range on success (always `0..2^64` for Hathor's configuration); the Python and TypeScript bindings simplify this to a boolean.

The **generator** depends on the output type:
- **AmountShielded**: `generator = derive_asset_tag(token_uid)` -- the unblinded 33-byte generator
- **FullShielded**: `generator = output.asset_commitment` -- the blinded 33-byte generator

### 3.3 Surjection Proof Verification (FullShieldedOutput only)

Proves the hidden token type is one of the input token types -- without revealing which one.

The **domain** is the list of generators from all transaction inputs: use `derive_asset_tag(token_uid)` for transparent inputs, or the input's `asset_commitment` for shielded inputs. The **codomain** is the output's `asset_commitment`.

```rust
// Rust
use hathor_ct_crypto::surjection::verify_surjection_proof;

verify_surjection_proof(&proof, &codomain, &domain)?;
```

```python
# Python
valid: bool = ct.verify_surjection_proof(proof, codomain, domain)
```

```typescript
// TypeScript
const valid: boolean = verifySurjectionProof(proof, codomain, domain);
```

### 3.4 Balance Verification

Verifies the homomorphic balance equation. In the normal case (at least one shielded output, balanced by the sender via Section 2.3):

```
sum(C_in) = sum(C_out)
```

For a full unshield (shielded inputs, no shielded outputs), the sender supplied an excess scalar in an `UnshieldBalanceHeader` (Section 2.4); the verifier reconstructs `excess * G` on the output side:

```
sum(C_in) = sum(C_out) + excess * G
```

The `excess_blinding_factor` parameter is optional across all three bindings. Pass `None` / `null` / omit when the tx does not have an `UnshieldBalanceHeader`; pass the 32-byte scalar otherwise.

#### Rust

```rust
use hathor_ct_crypto::balance::{BalanceEntry, verify_balance};

// No excess (normal path).
verify_balance(&inputs, &outputs, None)?;

// Full-unshield path.
verify_balance(&inputs, &outputs, Some(tweak_from_excess))?;
```

#### Python

```python
# Normal path (excess defaults to None).
valid: bool = ct.verify_balance(
    [(100, token_uid)],         # transparent inputs
    [shielded_commitment],      # shielded input commitments (33 B each)
    [(50, token_uid)],          # transparent outputs
    [shielded_commitment_out],  # shielded output commitments (33 B each)
)

# Full-unshield path: pass excess as the fifth positional arg (or kwarg).
valid = ct.verify_balance(
    [(100, token_uid)],         # transparent inputs (possibly empty)
    [shielded_commitment],      # shielded input commitment(s)
    [(100, token_uid)],         # transparent outputs + any transparent fees
    [],                          # shielded outputs MUST be empty
    excess_blinding_factor,     # 32-byte scalar from the UnshieldBalanceHeader
)
```

#### TypeScript

```typescript
// Normal path.
const valid: boolean = verifyBalance(
  [{ amount: 100, tokenUid: htrUid }],   // transparent inputs
  [shieldedInputCommitment],               // shielded inputs
  [{ amount: 50, tokenUid: htrUid }],     // transparent outputs
  [shieldedOutputCommitment],              // shielded outputs
);

// Full-unshield path.
const validUnshield: boolean = verifyBalance(
  [],                                            // transparent inputs
  [shieldedInputCommitment],                    // shielded input(s)
  [{ amount: 100, tokenUid: htrUid }],          // transparent outputs + fees
  [],                                            // shielded outputs MUST be empty
  excessBlindingFactor,                          // 32-byte Buffer
);
```

> Python uses tuples `(amount, token_uid)` for transparent entries; TypeScript uses objects `{ amount, tokenUid }`. The excess parameter is always a raw 32-byte value (`bytes` in Python, `Buffer` in TypeScript, `Tweak`/`[u8; 32]` in Rust).

#### Balance with Mint/Melt headers

When the transaction carries a `MintHeader` or `MeltHeader` (the
shielded-mint/melt extension), the caller folds each header entry into the
transparent-side lists *before* calling `verify_balance`. The crypto API
itself does not change — only the tuples you pass in.

For each token `T` referenced by a `MintHeader` entry `(token_index, amount)`:

- Append `(amount, token_uid_T)` to **transparent inputs**. The minted scalar
  enters the input side of the balance equation as an unblinded term.
- If `T` is `DEPOSIT`-version: append `(deposit, HTR_uid)` to **transparent
  outputs**, where `deposit = ceil(0.01 × amount)`. Skip when `deposit == 0`.
- If `T` is `FEE`-version: append `(FEE_PER_OUTPUT, HTR_uid)` to **transparent
  outputs**. The charge is one `FEE_PER_OUTPUT` per `MintHeader` entry,
  regardless of how many shielded recipients the entry is split across.

Symmetric for each `MeltHeader` entry `(token_index, amount)`:

- Append `(amount, token_uid_T)` to **transparent outputs**.
- If `T` is `DEPOSIT`-version: append `(withdraw, HTR_uid)` to **transparent
  inputs**, where `withdraw = floor(0.01 × amount)`. Skip when `withdraw == 0`.
- If `T` is `FEE`-version: append `(FEE_PER_OUTPUT, HTR_uid)` to **transparent
  outputs** (the per-entry charge is paid by the user on melt as well as on
  mint).

Notes:

- The FEE-token per-entry `FEE_PER_OUTPUT` charge is folded into the balance
  equation directly — it is NOT declared in the `FeeHeader`. `FeeHeader`
  continues to cover only chargeable transparent outputs and shielded
  outputs.
- All token UIDs must be normalized to 32 bytes before being passed to
  `verify_balance` (HTR's 1-byte UID is left-padded with zeros to 32 bytes).
- A token cannot appear in both `MintHeader` and `MeltHeader` in the same
  transaction (RFC Rule M3), so the input and output sides of the
  augmentation never overlap on the same token.

Worked example: shielded mint of 10,000 units of a `DEPOSIT`-version token
`TD` to two shielded recipients, with a `FEE_PER_OUTPUT` of 100 HTR.

```python
# Existing transparent flow (mint authority input has value 0).
transparent_inputs = []
transparent_outputs = []

# MintHeader entry: (token_index=1, amount=10_000)
transparent_inputs.append((10_000, td_uid_32B))   # primary side
transparent_outputs.append((100, htr_uid_32B))    # 1% deposit (10_000 * 0.01)

# Two AmountShieldedOutputs of TD (commitments encode the 10_000 split).
shielded_outputs = [commit_a, commit_b]
shielded_inputs = []

valid = ct.verify_balance(
    transparent_inputs,
    shielded_inputs,
    transparent_outputs,
    shielded_outputs,
)
```

Same example with a `FEE`-version token `TF`:

```python
# MintHeader entry: (token_index=1, amount=10_000)
transparent_inputs.append((10_000, tf_uid_32B))   # primary side
transparent_outputs.append((100, htr_uid_32B))    # FEE_PER_OUTPUT (per-entry)

# ...same shielded outputs and verify_balance call as above.
```

#### Structural invariants (enforced at the FFI boundary)

When `excess_blinding_factor` is present, the bindings validate three invariants *before* doing any cryptographic work and reject with a binding-native error (`ValueError` in Python, thrown `Error` in TypeScript, `Err` in Rust FFI):

| Invariant | Error message |
|-----------|--------------|
| excess and shielded outputs cannot coexist | `excess_blinding_factor must be None when shielded_outputs is non-empty` |
| excess requires at least one shielded input | `excess_blinding_factor requires at least one shielded input` |
| excess scalar must be 32 bytes | `must be 32 bytes` |

Explorers and full nodes should additionally enforce, at the transaction-header layer:

| Invariant | Where |
|-----------|-------|
| A shielded tx with shielded inputs and no shielded outputs must carry an `UnshieldBalanceHeader` (full unshields cannot omit it) | Python node: `ShieldedBalanceMismatchError("a full-unshield tx ... must carry an unshield balance header")` |
| A tx must not carry both an `UnshieldBalanceHeader` and a `ShieldedOutputsHeader` | Python node: `ShieldedBalanceMismatchError("a shielded tx cannot carry both shielded outputs and an unshield balance header")` |
| `UnshieldBalanceHeader` requires at least one shielded input | Python node: `ShieldedBalanceMismatchError("unshield balance header requires at least one shielded input")` |

---

## 4. Rewinding Shielded Outputs (Recipient)

The recipient uses their private key and the on-chain `ephemeral_pubkey` to recover the hidden values. This is a single function call per output type.

### 4.1 AmountShieldedOutput

The recipient already knows the `token_uid` from the visible `token_data` field.

#### Rust

```rust
use hathor_ct_crypto::ecdh::rewind_amount_shielded_output;

let result = rewind_amount_shielded_output(
    &my_private_key,      // 32 B
    &output.ephemeral_pubkey,  // 33 B from on-chain
    &output.commitment,
    &output.range_proof,
    &token_uid,           // known from token_data
)?;

result.value           // u64, the hidden amount
result.blinding_factor // Vec<u8>, 32 B (needed to spend this output)
```

#### Python

```python
result = ct.rewind_amount_shielded_output(
    my_private_key,
    output.ephemeral_pubkey,
    output.commitment,
    output.range_proof,
    token_uid,
)

result.value            # int
result.blinding_factor  # bytes, 32 B
```

#### TypeScript

```typescript
import { rewindAmountShieldedOutput } from 'hathor-ct-crypto';

const result = rewindAmountShieldedOutput(
  myPrivateKey,
  output.ephemeralPubkey,
  output.commitment,
  output.rangeProof,
  tokenUid,
);

result.value;           // number
result.blindingFactor;  // Buffer, 32 B
```

### 4.2 FullShieldedOutput

The token UID is hidden, so the recipient recovers it from the range proof message along with the asset blinding factor.

#### Rust

```rust
use hathor_ct_crypto::ecdh::rewind_full_shielded_output;

let result = rewind_full_shielded_output(
    &my_private_key,
    &output.ephemeral_pubkey,
    &output.commitment,
    &output.range_proof,
    &output.asset_commitment,  // used as the generator
)?;

result.value                  // u64
result.blinding_factor        // Vec<u8>, 32 B
result.token_uid              // [u8; 32], recovered from proof message
result.asset_blinding_factor  // [u8; 32], recovered from proof message
```

#### Python

```python
result = ct.rewind_full_shielded_output(
    my_private_key,
    output.ephemeral_pubkey,
    output.commitment,
    output.range_proof,
    output.asset_commitment,
)

result.value                  # int
result.blinding_factor        # bytes, 32 B
result.token_uid              # bytes, 32 B
result.asset_blinding_factor  # bytes, 32 B
```

#### TypeScript

```typescript
import { rewindFullShieldedOutput } from 'hathor-ct-crypto';

const result = rewindFullShieldedOutput(
  myPrivateKey,
  output.ephemeralPubkey,
  output.commitment,
  output.rangeProof,
  output.assetCommitment,
);

result.value;                 // number
result.blindingFactor;        // Buffer, 32 B
result.tokenUid;              // Buffer, 32 B
result.assetBlindingFactor;   // Buffer, 32 B
```

### 4.3 Cross-checking FullShielded Token UID

After rewinding a `FullShieldedOutput`, the wallet **must** verify that the recovered `token_uid` is consistent with the on-chain `asset_commitment`. An attacker could embed an incorrect token UID in the range proof message.

The verification reconstructs the expected asset commitment from the recovered values using two helper functions:
- `derive_tag(token_uid)` -- produces a 32-byte raw tag from the token UID
- `create_asset_commitment(tag, abf)` -- produces the 33-byte blinded generator from a raw tag and asset blinding factor

(These differ from `derive_asset_tag(token_uid)`, which produces a 33-byte **unblinded** generator used in range proof verification.)

#### Python

```python
expected_tag = ct.derive_tag(result.token_uid)
expected_ac = ct.create_asset_commitment(expected_tag, result.asset_blinding_factor)
assert expected_ac == output.asset_commitment, "token UID mismatch -- asset commitment verification failed"
```

#### Rust

```rust
use hathor_ct_crypto::generators::{derive_tag, create_asset_commitment};

let expected_tag = derive_tag(&result.token_uid)?;
let expected_ac = create_asset_commitment(&expected_tag, &result.asset_blinding_factor)?;
assert_eq!(expected_ac, output.asset_commitment, "token UID mismatch");
```

#### TypeScript

```typescript
import { deriveTag, createAssetCommitment } from 'hathor-ct-crypto';

const expectedTag = deriveTag(result.tokenUid);
const expectedAc = createAssetCommitment(expectedTag, result.assetBlindingFactor);
assert(expectedAc.equals(output.assetCommitment), 'token UID mismatch');
```

### 4.4 Behavior on Recipient Mismatch

If the rewind nonce doesn't match (wrong recipient), the rewind call raises an error (Python: `ValueError`, Rust: `Err(HathorCtError)`, TypeScript: thrown `Error`). The rewind nonce is derived from the ECDH shared secret, which is unique per sender-recipient-ephemeral triple, so a mismatched key always produces an invalid nonce -- there are no false positives.

---

## 5. Error Handling

| Error category | Recoverable? | Cause |
|---------------|-------------|-------|
| Invalid public key | No | Malformed 33-byte key input (not a valid curve point) |
| Invalid blinding factor | No | Scalar is zero or >= curve order -- use `generate_random_blinding_factor()` |
| Invalid excess blinding factor size | No | `excess_blinding_factor` must be exactly 32 bytes (Section 2.4) |
| Excess + shielded outputs both present | No | Violates mutual-exclusion; the tx is malformed (Section 3.4) |
| Excess without shielded inputs | No | Meaningless scalar; the tx is malformed (Section 3.4) |
| Range proof creation failure | No | Internal error (should not happen with valid inputs) |
| Range proof verification failure | N/A | Returns `false` (Python/TS) or `Err` (Rust) -- the proof is invalid |
| Surjection proof verification failure | N/A | Returns `false` / `Err` -- the proof is invalid |
| Balance verification failure (wrong excess) | N/A | Returns `false` / `Err` -- `excess * G` does not close the equation |
| Rewind failure (wrong key) | Expected | Not your output -- this is the normal "not for me" signal |
| Rewind failure (corrupted data) | No | On-chain data is malformed |

"No" means a programming error -- fix the input, don't retry. "Expected" means this is normal operation (scanning outputs you don't own).

---

## 6. ECDH Internals

The high-level functions above handle ECDH internally. These low-level primitives are exposed for specific use cases such as custom recovery flows or delegated scanning.

| Function | Description |
|----------|-------------|
| `generate_random_blinding_factor()` | Random valid secp256k1 scalar (32 B) |
| `generate_ephemeral_keypair()` | Fresh secp256k1 keypair: `(privkey_32B, pubkey_33B)` |
| `derive_ecdh_shared_secret(privkey, peer_pubkey)` | `SHA256(version_byte \|\| x)` of shared EC point (32 B) |
| `derive_rewind_nonce(shared_secret)` | `SHA256("Hathor_CT_nonce_v1" \|\| shared_secret)` (32 B) |
| `rewind_range_proof(proof, commitment, nonce, generator)` | Returns `(value, blinding_factor, message)` -- the low-level rewind used internally |
| `derive_tag(token_uid)` | Raw 32-byte tag from token UID (for surjection proofs and `create_asset_commitment`) |
| `derive_asset_tag(token_uid)` | Unblinded 33-byte generator from token UID (for range proof verification) |
| `create_asset_commitment(tag, r_asset)` | Blinded 33-byte generator from raw tag + asset blinding factor |

**Recovery flow (manual):**

```
sender:    s = derive_ecdh_shared_secret(ephemeral_privkey, recipient_pubkey)
recipient: s = derive_ecdh_shared_secret(recipient_privkey, ephemeral_pubkey)
           // Both produce the same 32-byte shared secret

nonce = derive_rewind_nonce(s)
(value, blinding, message) = rewind_range_proof(proof, commitment, nonce, generator)
```

---

## 7. Key Sizes Reference

| Value | Size | Notes |
|-------|------|-------|
| Private key | 32 B | secp256k1 scalar |
| Public key (compressed) | 33 B | `02`/`03` prefix + x-coordinate |
| Pedersen commitment | 33 B | Compressed curve point |
| Generator / asset tag | 33 B | Compressed curve point (from `derive_asset_tag`) |
| Raw tag | 32 B | From `derive_tag` (used for surjection proofs and `create_asset_commitment`) |
| Blinding factor (value) | 32 B | secp256k1 scalar |
| Blinding factor (asset) | 32 B | secp256k1 scalar |
| Excess blinding factor | 32 B | secp256k1 scalar; revealed in `UnshieldBalanceHeader` on full unshields |
| Shared secret | 32 B | SHA256 output |
| Rewind nonce | 32 B | SHA256 output |
| Token UID | 32 B | HTR = `0x00 * 32` |
| Range proof | ~675 B | Bulletproof; hard upper bound 1024 B (safe for buffer allocation) |
| Surjection proof | ~130 B | Depends on domain size; hard upper bound 4096 B |
