# Shielded Outputs: Client Integration Guide

This guide explains how wallets and explorers interact with Hathor's shielded outputs using the `hathor-ct-crypto` library. The same Rust core powers all three bindings: Rust (direct), Python (PyO3), and Node.js/TypeScript (NAPI).

---

## 1. Output Types

Hathor offers two privacy tiers for shielded outputs. Both attach to regular transactions via a `ShieldedOutputsHeader` -- no new transaction version is needed.

### AmountShieldedOutput

Hides the **amount**. The token type remains visible.

| Field | Size | Description |
|-------|------|-------------|
| `commitment` | 33 B | Pedersen commitment `C = value * H_token + r * G` |
| `range_proof` | ~675 B | Bulletproof proving value is in [1, 2^64) |
| `script` | variable | Locking script (P2PKH, etc.) |
| `token_data` | 1 B | Token index (same as `TxOutput.token_data`) |
| `ephemeral_pubkey` | 33 B | Sender's ephemeral public key for ECDH recovery |

**Use when:** the token type is not sensitive (e.g., HTR transfers).

### FullShieldedOutput

Hides **both** the amount and the token type.

| Field | Size | Description |
|-------|------|-------------|
| `commitment` | 33 B | Pedersen commitment using blinded generator |
| `range_proof` | ~675 B | Bulletproof (embeds encrypted token UID + asset blinding in message) |
| `script` | variable | Locking script |
| `asset_commitment` | 33 B | Blinded asset tag `A = H_token + r_asset * G` |
| `surjection_proof` | ~130 B | Proves the hidden token is one of the input tokens |
| `ephemeral_pubkey` | 33 B | Sender's ephemeral public key for ECDH recovery |

**Use when:** the token type is sensitive (e.g., custom tokens, stablecoins).

---

## 2. Creating Shielded Outputs

The high-level `create_*` functions handle the full pipeline: ephemeral keypair generation, ECDH shared secret, nonce derivation, Pedersen commitment, and Bulletproof range proof -- in a single call.

### 2.1 AmountShieldedOutput

#### Rust

```rust
use hathor_ct_crypto::ecdh::create_amount_shielded_output;

let value: u64 = 5000;
let recipient_pubkey: &[u8; 33] = /* recipient's compressed secp256k1 pubkey */;
let token_uid: [u8; 32] = [0u8; 32]; // HTR = all zeros
let vbf: [u8; 32] = rand::random();  // random value blinding factor

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
import os
import hathor_ct_crypto as ct

value = 5000
recipient_pubkey = b'\x02...'  # 33-byte compressed pubkey
token_uid = b'\x00' * 32       # HTR
vbf = os.urandom(32)           # random value blinding factor

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
  type CreatedAmountShieldedOutput,
} from 'hathor-ct-crypto';
import { randomBytes } from 'crypto';

const value = 5000;
const recipientPubkey: Buffer = /* 33-byte compressed pubkey */;
const tokenUid = Buffer.alloc(32); // HTR
const vbf = randomBytes(32);

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

#### Rust

```rust
use hathor_ct_crypto::ecdh::create_full_shielded_output;

let value: u64 = 7777;
let recipient_pubkey: &[u8; 33] = /* ... */;
let token_uid: [u8; 32] = /* actual token UID, 32 bytes */;
let vbf: [u8; 32] = rand::random();  // value blinding factor
let abf: [u8; 32] = rand::random();  // asset blinding factor

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

For a transaction to be valid, blinding factors must **balance**: the sum of input blindings must equal the sum of output blindings (per token). Assign random blinding factors to all outputs except the last, then compute the balancing factor:

```python
# Python example
last_vbf = ct.compute_balancing_blinding_factor(
    value=last_output_value,
    generator_blinding_factor=last_abf,  # b'\x00'*32 for AmountShielded
    inputs=[(val, vbf, gbf) for each input],
    other_outputs=[(val, vbf, gbf) for each other output],
)
```

```typescript
// TypeScript example
const lastVbf = computeBalancingBlindingFactor(
  lastOutputValue,
  lastAbf,  // Buffer.alloc(32) for AmountShielded
  inputs.map(i => ({ value: i.value, valueBlindingFactor: i.vbf, generatorBlindingFactor: i.gbf })),
  otherOutputs.map(o => ({ value: o.value, valueBlindingFactor: o.vbf, generatorBlindingFactor: o.gbf })),
);
```

---

## 3. Verifying Shielded Outputs

Full nodes and explorers verify shielded outputs without knowing the hidden values.

### 3.1 Range Proof Verification

Proves the committed value is in [1, 2^64) -- i.e., no negative or zero amounts.

```rust
// Rust
use hathor_ct_crypto::rangeproof::verify_range_proof;

let valid = verify_range_proof(&proof, &commitment, &generator)?;
// valid: Range<u64> on success, Err on failure
```

```python
# Python
valid: bool = ct.verify_range_proof(proof, commitment, generator)
```

```typescript
// TypeScript
const valid: boolean = verifyRangeProof(proof, commitment, generator);
```

The **generator** depends on the output type:
- **AmountShielded**: `generator = derive_asset_tag(token_uid)`
- **FullShielded**: `generator = output.asset_commitment`

### 3.2 Surjection Proof Verification (FullShieldedOutput only)

Proves the hidden token type is one of the input token types -- without revealing which one.

```python
# Python
# codomain: the output's blinded asset commitment (33 B)
# domain: list of blinded generators from the inputs (33 B each)
valid: bool = ct.verify_surjection_proof(proof, codomain, domain)
```

```typescript
// TypeScript
const valid: boolean = verifySurjectionProof(proof, codomain, domain);
```

### 3.3 Balance Verification

Verifies the homomorphic balance equation: sum of input commitments equals sum of output commitments (per token). Supports mixed transactions with both transparent and shielded inputs/outputs.

```python
# Python
valid: bool = ct.verify_balance(
    transparent_inputs=[(amount, token_uid_32B), ...],
    shielded_inputs=[commitment_33B, ...],
    transparent_outputs=[(amount, token_uid_32B), ...],
    shielded_outputs=[commitment_33B, ...],
)
```

```typescript
// TypeScript
const valid: boolean = verifyBalance(
  [{ amount: 100, tokenUid: htrUid }],   // transparent inputs
  [shieldedInputCommitment],               // shielded inputs
  [{ amount: 50, tokenUid: htrUid }],     // transparent outputs
  [shieldedOutputCommitment],              // shielded outputs
);
```

### 3.4 Point Validation

Before processing, validate that commitments and generators are valid secp256k1 curve points:

```python
assert ct.validate_commitment(output.commitment)   # 33 B
assert ct.validate_generator(output.asset_commitment)  # 33 B (FullShielded)
```

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

After rewinding a `FullShieldedOutput`, the wallet **must** verify the recovered `token_uid` matches the on-chain `asset_commitment`. A malicious sender could embed a fraudulent token UID in the message.

```python
# Reconstruct expected asset commitment from recovered values
expected_tag = ct.derive_tag(result.token_uid)
expected_ac = ct.create_asset_commitment(expected_tag, result.asset_blinding_factor)
assert expected_ac == output.asset_commitment, "token UID mismatch -- possible fraud"
```

### 4.4 Wrong Key Behavior

If the rewind nonce doesn't match (wrong recipient), the rewind call raises an error (Python: `ValueError`, Rust: `Err(HathorCtError)`, TypeScript: thrown `Error`). This is by design -- there are no false positives.

---

## 5. ECDH Internals (Low-Level)

The high-level functions above handle ECDH internally. These low-level primitives are exposed for advanced use cases (e.g., custom recovery flows, delegated scanning).

| Function | Description |
|----------|-------------|
| `generate_ephemeral_keypair()` | Fresh secp256k1 keypair: `(privkey_32B, pubkey_33B)` |
| `derive_ecdh_shared_secret(privkey, peer_pubkey)` | `SHA256(version_byte \|\| x)` of shared EC point (32 B) |
| `derive_rewind_nonce(shared_secret)` | `SHA256("Hathor_CT_nonce_v1" \|\| shared_secret)` (32 B) |

**Recovery flow (manual):**

```
sender:    s = derive_ecdh_shared_secret(ephemeral_privkey, recipient_pubkey)
recipient: s = derive_ecdh_shared_secret(recipient_privkey, ephemeral_pubkey)
           // Both produce the same 32-byte shared secret

nonce = derive_rewind_nonce(s)
(value, blinding, message) = rewind_range_proof(proof, commitment, nonce, generator)
```

---

## 6. Key Sizes Reference

| Value | Size | Notes |
|-------|------|-------|
| Private key | 32 B | secp256k1 scalar |
| Public key (compressed) | 33 B | `02`/`03` prefix + x-coordinate |
| Pedersen commitment | 33 B | Compressed curve point |
| Generator / asset tag | 33 B | Compressed curve point |
| Raw tag (surjection) | 32 B | Used for surjection proof domain |
| Blinding factor (value) | 32 B | secp256k1 scalar |
| Blinding factor (asset) | 32 B | secp256k1 scalar |
| Shared secret | 32 B | SHA256 output |
| Rewind nonce | 32 B | SHA256 output |
| Token UID | 32 B | HTR = `0x00 * 32` |
| Range proof | ~675 B | Bulletproof (max 1024 B) |
| Surjection proof | ~130 B | Depends on domain size (max 4096 B) |
