// End-to-end tests for BigInt support at the napi boundary.
//
// The Rust unit tests (`cargo test --features napi --lib`) cover the
// `bigint_to_u64` helper in isolation. These tests exercise the full JS↔Rust
// round-trip: a BigInt passed from JS is accepted by the binding, used in a
// u64-level computation, and (for the rewind path) returned back as a BigInt.

import test from 'node:test';
import assert from 'node:assert/strict';

import * as ctCrypto from '../index.js';

const {
  createCommitment,
  createTrivialCommitment,
  createAmountShieldedOutput,
  rewindAmountShieldedOutput,
  createShieldedOutputWithBothBlindings,
  rewindFullShieldedOutput,
  verifyBalance,
  htrAssetTag,
  generateEphemeralKeypair,
  generateRandomBlindingFactor,
  getCommitmentSize,
} = ctCrypto;

const U64_MAX = (1n << 64n) - 1n;
const JS_SAFE_MAX = BigInt(Number.MAX_SAFE_INTEGER); // 2^53 - 1
// Range proof bit width (see RANGE_PROOF_BITS in src/rangeproof.rs). Shielded
// outputs can only commit values in [1, 2^40), so the max value that survives a
// createAmountShieldedOutput / rewind round trip is 2^40 - 1.
const RANGE_PROOF_MAX = (1n << 40n) - 1n;

// Realistic Hathor transaction magnitudes (in atomic units). All fit in JS
// Number, but must also flow through the bigint-typed API.
const HATHOR_AMOUNTS = [
  { label: '100 million', value: 100_000_000n },
  { label: '1 billion', value: 1_000_000_000n },
  { label: '100 billion', value: 100_000_000_000n },
];

// --- createCommitment -------------------------------------------------------

test('createCommitment accepts BigInt across the full u64 range', () => {
  const blinding = generateRandomBlindingFactor();
  const generator = htrAssetTag();

  const values = [0n, 1n, JS_SAFE_MAX, JS_SAFE_MAX + 1n, 1n << 60n, U64_MAX];
  for (const amount of values) {
    const c = createCommitment(amount, blinding, generator);
    assert.equal(c.length, getCommitmentSize(), `length for amount=${amount}`);
  }
});

for (const { label, value } of HATHOR_AMOUNTS) {
  test(`createCommitment accepts ${label} (${value})`, () => {
    const blinding = generateRandomBlindingFactor();
    const generator = htrAssetTag();
    const c = createCommitment(value, blinding, generator);
    assert.equal(c.length, getCommitmentSize());
  });
}

test('createCommitment rejects Number (must be BigInt)', () => {
  const blinding = generateRandomBlindingFactor();
  const generator = htrAssetTag();
  assert.throws(() => createCommitment(123, blinding, generator), {
    code: 'BigintExpected',
  });
});

test('createCommitment rejects negative BigInt', () => {
  const blinding = generateRandomBlindingFactor();
  const generator = htrAssetTag();
  assert.throws(() => createCommitment(-1n, blinding, generator), {
    message: /non-negative/,
  });
});

test('createCommitment rejects BigInt above u64::MAX', () => {
  const blinding = generateRandomBlindingFactor();
  const generator = htrAssetTag();
  assert.throws(() => createCommitment(U64_MAX + 1n, blinding, generator), {
    message: /exceeds u64 range/,
  });
  assert.throws(() => createCommitment(1n << 128n, blinding, generator), {
    message: /exceeds u64 range/,
  });
});

// --- createTrivialCommitment ------------------------------------------------

test('createTrivialCommitment accepts BigInt above JS safe integer', () => {
  const c = createTrivialCommitment(JS_SAFE_MAX + 42n, htrAssetTag());
  assert.equal(c.length, getCommitmentSize());
});

test('createTrivialCommitment rejects overflow BigInt', () => {
  assert.throws(() => createTrivialCommitment(U64_MAX + 1n, htrAssetTag()), {
    message: /exceeds u64 range/,
  });
});

// --- AmountShielded round-trip ---------------------------------------------

for (const { label, value } of HATHOR_AMOUNTS) {
  test(`AmountShielded output round-trips ${label} (${value})`, () => {
    const { privateKey, publicKey } = generateEphemeralKeypair();
    const tokenUid = Buffer.alloc(32, 9);
    const vbf = generateRandomBlindingFactor();

    const created = createAmountShieldedOutput(value, publicKey, tokenUid, vbf);
    const rewound = rewindAmountShieldedOutput(
      privateKey,
      created.ephemeralPubkey,
      created.commitment,
      created.rangeProof,
      tokenUid,
    );
    assert.equal(typeof rewound.value, 'bigint');
    assert.equal(rewound.value, value);
  });
}

test('AmountShielded output round-trips RANGE_PROOF_MAX (2^40 - 1)', () => {
  // Upper bound of the current 40-bit range proof. Above this the range proof
  // itself fails — the BigInt boundary is fine, the crypto is what caps out.
  const value = RANGE_PROOF_MAX;
  const { privateKey, publicKey } = generateEphemeralKeypair();
  const tokenUid = Buffer.alloc(32, 3);
  const vbf = generateRandomBlindingFactor();

  const created = createAmountShieldedOutput(value, publicKey, tokenUid, vbf);
  const rewound = rewindAmountShieldedOutput(
    privateKey,
    created.ephemeralPubkey,
    created.commitment,
    created.rangeProof,
    tokenUid,
  );
  assert.equal(rewound.value, value);
});

test('AmountShielded output rejects negative BigInt', () => {
  const { publicKey } = generateEphemeralKeypair();
  const vbf = generateRandomBlindingFactor();
  assert.throws(
    () => createAmountShieldedOutput(-1n, publicKey, Buffer.alloc(32), vbf),
    { message: /non-negative/ },
  );
});

test('AmountShielded output rejects BigInt above u64::MAX', () => {
  const { publicKey } = generateEphemeralKeypair();
  const vbf = generateRandomBlindingFactor();
  assert.throws(
    () => createAmountShieldedOutput(U64_MAX + 1n, publicKey, Buffer.alloc(32), vbf),
    { message: /exceeds u64 range/ },
  );
});

// --- FullShielded round-trip ------------------------------------------------

for (const { label, value } of HATHOR_AMOUNTS) {
  test(`FullShielded output round-trips ${label} (${value})`, () => {
    const { privateKey, publicKey } = generateEphemeralKeypair();
    const tokenUid = Buffer.alloc(32, 0xab);
    const vbf = generateRandomBlindingFactor();
    const abf = generateRandomBlindingFactor();

    const created = createShieldedOutputWithBothBlindings(
      value, publicKey, tokenUid, vbf, abf,
    );
    const rewound = rewindFullShieldedOutput(
      privateKey,
      created.ephemeralPubkey,
      created.commitment,
      created.rangeProof,
      created.assetCommitment,
    );
    assert.equal(typeof rewound.value, 'bigint');
    assert.equal(rewound.value, value);
    assert.deepEqual(Buffer.from(rewound.tokenUid), tokenUid);
  });
}

// --- verifyBalance / TransparentEntry ---------------------------------------

for (const { label, value } of HATHOR_AMOUNTS) {
  test(`verifyBalance balances ${label} transparent in == transparent out`, () => {
    const tokenUid = Buffer.alloc(32, 1);
    const ok = verifyBalance(
      [{ amount: value, tokenUid }],
      [],
      [{ amount: value, tokenUid }],
      [],
    );
    assert.equal(ok, true);
  });
}

test('verifyBalance handles TransparentEntry amounts above JS safe integer', () => {
  const tokenUid = Buffer.alloc(32, 1);
  const amount = JS_SAFE_MAX + 99n;
  const ok = verifyBalance(
    [{ amount, tokenUid }],
    [],
    [{ amount, tokenUid }],
    [],
  );
  assert.equal(ok, true);
});

test('verifyBalance TransparentEntry rejects negative amount', () => {
  const tokenUid = Buffer.alloc(32, 1);
  assert.throws(
    () => verifyBalance([{ amount: -1n, tokenUid }], [], [], []),
    { message: /non-negative/ },
  );
});

test('verifyBalance TransparentEntry rejects overflow amount', () => {
  const tokenUid = Buffer.alloc(32, 1);
  assert.throws(
    () => verifyBalance([{ amount: U64_MAX + 1n, tokenUid }], [], [], []),
    { message: /exceeds u64 range/ },
  );
});
