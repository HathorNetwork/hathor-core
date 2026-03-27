# Shielded Outputs: Client Integration Guide

This guide explains how wallets and explorers interact with Hathor's shielded outputs using the `hathor-ct-crypto` library. All three bindings -- Rust (direct), Python (PyO3), and Node.js/TypeScript (NAPI) -- wrap the same Rust implementation.

> **Scope:** This guide covers creating, verifying, and recovering shielded outputs. Transaction assembly (attaching outputs to a `ShieldedOutputsHeader`) and spending shielded outputs are covered in the transaction format specification.

---

## Workflow Overview

Shielded outputs attach to regular v1/v2 transactions via a `ShieldedOutputsHeader` -- no new transaction version is needed. A transaction can mix transparent and shielded outputs freely.

**Sender workflow:**

1. Generate blinding factors (Section 2.0)
2. Create shielded outputs (Section 2.1 / 2.2)
3. Compute the balancing blinding factor for the last output (Section 2.3)
4. Attach outputs to the transaction's `ShieldedOutputsHeader`

**Verifier workflow (full nodes, explorers):**

1. Validate curve points (Section 3.1)
2. Verify range proofs (Section 3.2)
3. Verify surjection proofs for FullShielded outputs (Section 3.3)
4. Verify commitment balance (Section 3.4)

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

Verifies the homomorphic balance equation: sum of input commitments equals sum of output commitments (per token). Supports mixed transactions with both transparent and shielded inputs/outputs.

```python
# Python -- uses positional args with tuples: (amount, token_uid_32B)
valid: bool = ct.verify_balance(
    [(100, token_uid)],         # transparent inputs
    [shielded_commitment],      # shielded input commitments (33 B each)
    [(50, token_uid)],          # transparent outputs
    [shielded_commitment_out],  # shielded output commitments (33 B each)
)
```

```typescript
// TypeScript -- uses objects: { amount, tokenUid }
const valid: boolean = verifyBalance(
  [{ amount: 100, tokenUid: htrUid }],   // transparent inputs
  [shieldedInputCommitment],               // shielded inputs
  [{ amount: 50, tokenUid: htrUid }],     // transparent outputs
  [shieldedOutputCommitment],              // shielded outputs
);
```

> Python uses tuples `(amount, token_uid)` for transparent entries; TypeScript uses objects `{ amount, tokenUid }`.

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
| Range proof creation failure | No | Internal error (should not happen with valid inputs) |
| Range proof verification failure | N/A | Returns `false` (Python/TS) or `Err` (Rust) -- the proof is invalid |
| Surjection proof verification failure | N/A | Returns `false` / `Err` -- the proof is invalid |
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
| Shared secret | 32 B | SHA256 output |
| Rewind nonce | 32 B | SHA256 output |
| Token UID | 32 B | HTR = `0x00 * 32` |
| Range proof | ~675 B | Bulletproof; hard upper bound 1024 B (safe for buffer allocation) |
| Surjection proof | ~130 B | Depends on domain size; hard upper bound 4096 B |
