/*
 * Wallet-scan benchmark — Node binding (@hathor/ct-crypto-node).
 *
 * Node-side twin of benchmark_wallet_scan.py. Same scenario, same tx shapes,
 * same 7-phase timed wallet pass, same CSV schema — but the crypto is provided
 * by the `@hathor/ct-crypto-node` NAPI native addon instead of the Python FFI,
 * so the two rows in results_wallet/wallet_scan.csv (binding=python-ffi vs
 * binding=node-napi) isolate the binding/runtime overhead.
 *
 * NOTE on "WebAssembly": @hathor/ct-crypto-node is a NAPI native addon, not a
 * wasm module. It is the binding the project actually ships, modelled here per
 * request. A genuine wasm binding would need a wasm32 build of hathor-ct-crypto
 * (the crate currently builds a PyO3 extension + a NAPI addon, no wasm target).
 *
 * Requires Node >= 18 and `npm install @hathor/ct-crypto-node` (a prebuilt
 * native binary for your platform). Run standalone:
 *
 *   node benchmark_wallet_scan_node.js -N 150 -M 1 --total-outputs 2 \
 *     -Q 0 --total-inputs 1 -k 64 --runs 3
 *
 * or via the Python launcher: `... benchmark_wallet_scan.py --binding node-napi`.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let ct;
try {
  ct = require('@hathor/ct-crypto-node');
} catch (e) {
  console.error('Failed to load @hathor/ct-crypto-node. Install it first:\n' +
    '  npm install @hathor/ct-crypto-node   (needs Node >= 18 and a prebuilt binary for your platform)\n' +
    'Underlying error: ' + e.message);
  process.exit(1);
}

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const TOKEN_UID = Buffer.alloc(32, 0);          // HTR-like single token
const ZERO_TWEAK = ct.getZeroTweak();           // 32B zero blinding factor
const MAX_SURJECTION_RETRIES = 5;

// Dummy wallet scan key (the ECDH root secret). Generated once per process; it
// only has to be consistent within a run, exactly like the Python dummy key.
const SCAN = ct.generateEphemeralKeypair();     // { privateKey, publicKey }

const DEFAULTS = { n: 150, m: 1, mPrime: 2, q: 0, qPrime: 1, k: 64 };

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function randBytes(n) {
  return crypto.randomBytes(n);
}

function randomBigIntBelow(span) {  // uniform in [0, span), span: BigInt > 0
  const bits = span.toString(2).length;
  const nbytes = Math.ceil(bits / 8);
  const mask = (1n << BigInt(bits)) - 1n;
  for (;;) {
    let r = 0n;
    const buf = crypto.randomBytes(nbytes);
    for (const b of buf) r = (r << 8n) | BigInt(b);
    r = r & mask;
    if (r < span) return r;
  }
}

// Split `total` (BigInt) into `parts` positive BigInts summing to `total`.
function splitAmount(total, parts) {
  const base = total / BigInt(parts);
  const out = new Array(parts).fill(base);
  out[parts - 1] = out[parts - 1] + (total - base * BigInt(parts));
  return out;
}

// A per-tx k-bit value budget; every amount is a share of it, so all values are
// in [1, 2^k). Mirrors _pick_budget in the Python script.
function pickBudget(k, minParts) {
  const lo = 1n << BigInt(k - 1);
  const hi = (1n << BigInt(k)) - 1n;
  const span = hi - lo + 1n;
  const t = lo + (span > 1n ? randomBigIntBelow(span) : 0n);
  if (t < BigInt(minParts)) throw new Error(`k=${k} is too small to split into ${minParts} positive parts`);
  return t;
}

function makeSurjectionProof(tagRaw, rAsset, domainCreate) {
  for (let attempt = 0; attempt < MAX_SURJECTION_RETRIES; attempt++) {
    try {
      return ct.createSurjectionProof(tagRaw, rAsset, domainCreate);
    } catch (e) {
      if (attempt === MAX_SURJECTION_RETRIES - 1) throw e;
    }
  }
  throw new Error('unreachable');
}

// --------------------------------------------------------------------------
// Stream construction (NOT timed — wallet/network prep)
// --------------------------------------------------------------------------

function buildShieldedInput(amount) {
  const tagRaw = ct.deriveTag(TOKEN_UID);
  const rAsset = randBytes(32);
  const vbf = randBytes(32);
  const assetCommitment = ct.createAssetCommitment(tagRaw, rAsset);
  const commitment = ct.createCommitment(amount, vbf, assetCommitment);
  const rangeProof = ct.createRangeProof(amount, vbf, commitment, assetCommitment, null, null);
  return { amount, valueBlind: vbf, rAsset, assetCommitment, commitment, rangeProof };
}

function sealShieldedOutput(amount, vbf, rAsset, domainCreate) {
  const tagRaw = ct.deriveTag(TOKEN_UID);
  const assetCommitment = ct.createAssetCommitment(tagRaw, rAsset);
  const commitment = ct.createCommitment(amount, vbf, assetCommitment);

  const eph = ct.generateEphemeralKeypair();
  const shared = ct.deriveEcdhSharedSecret(eph.privateKey, SCAN.publicKey);
  const nonce = ct.deriveRewindNonce(shared);
  const message = Buffer.concat([TOKEN_UID, rAsset]);  // wallet reads [0:32], [32:64]

  const rangeProof = ct.createRangeProof(amount, vbf, commitment, assetCommitment, message, nonce);
  const surjectionProof = makeSurjectionProof(tagRaw, rAsset, domainCreate);

  return {
    amount, valueBlind: vbf, rAsset, assetCommitment, commitment,
    rangeProof, surjectionProof, ephemeralPubkey: eph.publicKey,
  };
}

function buildTx(m, mPrime, q, qPrime, k) {
  const total = pickBudget(k, Math.max(mPrime, qPrime));

  // ---- Inputs ----
  const inValues = splitAmount(total, qPrime);
  const transparentInValues = inValues.slice(0, qPrime - q);
  const shieldedInValues = inValues.slice(qPrime - q);
  const transparentInputs = transparentInValues.map((v) => ({ amount: v, tokenUid: TOKEN_UID }));
  const shieldedInputs = shieldedInValues.map((v) => buildShieldedInput(v));

  // Surjection domain = asset generators of ALL inputs.
  const tagRaw = ct.deriveTag(TOKEN_UID);
  const transparentGen = ct.deriveAssetTag(TOKEN_UID);
  const domainCreate = [];
  const domainVerify = [];
  for (let i = 0; i < transparentInputs.length; i++) {
    domainCreate.push({ generator: transparentGen, tag: tagRaw, blindingFactor: ZERO_TWEAK });
    domainVerify.push(transparentGen);
  }
  for (const inp of shieldedInputs) {
    domainCreate.push({ generator: inp.assetCommitment, tag: tagRaw, blindingFactor: inp.rAsset });
    domainVerify.push(inp.assetCommitment);
  }

  // ---- Outputs ----
  const outValues = splitAmount(total, mPrime);
  const transparentOutValues = outValues.slice(0, mPrime - m);
  const shieldedOutValues = outValues.slice(mPrime - m);
  const transparentOutputs = transparentOutValues.map((v) => ({ amount: v, tokenUid: TOKEN_UID }));

  // First M-1 shielded outputs get random blinding; the last one's value
  // blinding factor balances the homomorphic equation. Only shielded entries
  // feed the balancing computation (transparent are zero-blinded).
  const otherSecrets = [];  // { value, valueBlindingFactor, generatorBlindingFactor }
  for (let i = 0; i < shieldedOutValues.length - 1; i++) {
    otherSecrets.push({
      value: shieldedOutValues[i],
      valueBlindingFactor: randBytes(32),
      generatorBlindingFactor: randBytes(32),
    });
  }
  const lastValue = shieldedOutValues[shieldedOutValues.length - 1];
  const lastRAsset = randBytes(32);
  const inputsBf = shieldedInputs.map((inp) => ({
    value: inp.amount, valueBlindingFactor: inp.valueBlind, generatorBlindingFactor: inp.rAsset,
  }));
  const lastVbf = ct.computeBalancingBlindingFactor(lastValue, lastRAsset, inputsBf, otherSecrets);

  const shieldedOutputs = otherSecrets.map((s) =>
    sealShieldedOutput(s.value, s.valueBlindingFactor, s.generatorBlindingFactor, domainCreate));
  shieldedOutputs.push(sealShieldedOutput(lastValue, lastVbf, lastRAsset, domainCreate));

  return { transparentInputs, shieldedInputs, transparentOutputs, shieldedOutputs, domainVerify };
}

function buildStream(n, m, mPrime, q, qPrime, k) {
  const txs = [];
  for (let i = 0; i < n; i++) txs.push(buildTx(m, mPrime, q, qPrime, k));
  return txs;
}

// --------------------------------------------------------------------------
// The wallet pass (TIMED). hrtime.bigint() gives ns; we accumulate ns as Number.
// --------------------------------------------------------------------------

function walletPass(txs) {
  const t = { range: 0, surjection: 0, balance: 0, ecdh: 0, rewind: 0, recoverCheck: 0, update: 0, total: 0 };
  const balances = new Map();  // hex(tokenUid) -> BigInt

  const wall0 = process.hrtime.bigint();
  for (const tx of txs) {
    // 1. Range proofs — shielded outputs and shielded inputs (no batch API).
    let s = process.hrtime.bigint();
    for (const out of tx.shieldedOutputs) {
      assert(ct.verifyRangeProof(out.rangeProof, out.commitment, out.assetCommitment), 'range verify failed');
    }
    for (const inp of tx.shieldedInputs) {
      assert(ct.verifyRangeProof(inp.rangeProof, inp.commitment, inp.assetCommitment), 'range verify failed');
    }
    t.range += Number(process.hrtime.bigint() - s);

    // 2. Surjection proofs — one per shielded output, against the input domain.
    s = process.hrtime.bigint();
    for (const out of tx.shieldedOutputs) {
      assert(ct.verifySurjectionProof(out.surjectionProof, out.assetCommitment, tx.domainVerify),
        'surjection verify failed');
    }
    t.surjection += Number(process.hrtime.bigint() - s);

    // 3. Balance — single homomorphic check. Build lists outside the timer.
    const inCommits = tx.shieldedInputs.map((inp) => inp.commitment);
    const outCommits = tx.shieldedOutputs.map((out) => out.commitment);
    s = process.hrtime.bigint();
    assert(ct.verifyBalance(tx.transparentInputs, inCommits, tx.transparentOutputs, outCommits),
      'balance verify failed');
    t.balance += Number(process.hrtime.bigint() - s);

    // 4. Recover — ECDH-derive nonce, rewind, re-check. Three separate timers.
    const recovered = [];
    for (const out of tx.shieldedOutputs) {
      s = process.hrtime.bigint();
      const shared = ct.deriveEcdhSharedSecret(SCAN.privateKey, out.ephemeralPubkey);
      const nonce = ct.deriveRewindNonce(shared);
      t.ecdh += Number(process.hrtime.bigint() - s);

      s = process.hrtime.bigint();
      const rr = ct.rewindRangeProof(out.rangeProof, out.commitment, nonce, out.assetCommitment);
      t.rewind += Number(process.hrtime.bigint() - s);

      s = process.hrtime.bigint();
      const tokenId = rr.message.slice(0, 32);
      const assetBf = rr.message.slice(32, 64);
      // AUDIT-C015: reconstruct the asset commitment from recovered secrets.
      assert(ct.createAssetCommitment(ct.deriveTag(tokenId), assetBf).equals(out.assetCommitment),
        'recovered token UID does not match asset_commitment');
      assert(rr.value === out.amount, 'rewound value mismatch');
      t.recoverCheck += Number(process.hrtime.bigint() - s);

      recovered.push([tokenId, rr.value]);
    }

    // 5. Balance update — accumulate per-token totals.
    s = process.hrtime.bigint();
    for (const [tokenId, value] of recovered) {
      const key = tokenId.toString('hex');
      balances.set(key, (balances.get(key) || 0n) + value);
    }
    for (const o of tx.transparentOutputs) {
      const key = o.tokenUid.toString('hex');
      balances.set(key, (balances.get(key) || 0n) + o.amount);
    }
    t.update += Number(process.hrtime.bigint() - s);
  }
  t.total = Number(process.hrtime.bigint() - wall0);
  return { timing: t, balances };
}

// --------------------------------------------------------------------------
// Runner
// --------------------------------------------------------------------------

function safeMs(seconds, count) {
  return count ? (seconds / count) * 1000.0 : 0.0;
}

function run(opts) {
  validate(opts);
  const { n, m, mPrime, q, qPrime, k, runs, binding, outputDir } = opts;

  console.log(`Wallet-scan benchmark (Node) | N=${n} M=${m} M'=${mPrime} Q=${q} Q'=${qPrime} ` +
    `k=${k} runs=${runs} binding=${binding}`);
  console.log(`  node=${process.versions.node}  tx shape: ${q} shielded + ${qPrime - q} transparent ` +
    `inputs -> ${m} shielded + ${mPrime - m} transparent outputs`);

  const samples = [];
  for (let r = 0; r < runs; r++) {
    const txs = buildStream(n, m, mPrime, q, qPrime, k);  // prep: NOT timed
    const { timing } = walletPass(txs);                   // the timed scenario
    // ns -> seconds
    const sec = {};
    for (const key of Object.keys(timing)) sec[key] = timing[key] / 1e9;
    samples.push(sec);
    console.log(`  run ${r + 1}/${runs}: total=${sec.total.toFixed(3)}s ` +
      `[range=${sec.range.toFixed(3)} surj=${sec.surjection.toFixed(3)} bal=${sec.balance.toFixed(3)} ` +
      `ecdh=${sec.ecdh.toFixed(3)} rewind=${sec.rewind.toFixed(3)} recheck=${sec.recoverCheck.toFixed(4)} ` +
      `update=${sec.update.toFixed(4)}]`);
  }

  const mean = (key) => samples.reduce((a, s) => a + s[key], 0) / samples.length;
  const totalS = mean('total');
  const rangeS = mean('range');
  const surjS = mean('surjection');
  const balS = mean('balance');
  const ecdhS = mean('ecdh');
  const rewindS = mean('rewind');
  const recheckS = mean('recoverCheck');
  const updateS = mean('update');

  const nRange = n * (m + q);
  const nSurj = n * m;
  const nOut = n * m;
  const nBalance = n;

  console.log('');
  console.log(`  AVERAGE over ${runs} run(s): total ${totalS.toFixed(3)}s  (${(totalS / n * 1000).toFixed(3)} ms/tx)`);
  console.log(`    range       ${rangeS.toFixed(3)}s  ${safeMs(rangeS, nRange).toFixed(3)} ms/proof  (${nRange} proofs)`);
  console.log(`    surjection  ${surjS.toFixed(3)}s  ${safeMs(surjS, nSurj).toFixed(3)} ms/proof  (${nSurj} proofs)`);
  console.log(`    balance     ${balS.toFixed(3)}s  ${safeMs(balS, nBalance).toFixed(3)} ms/tx     (${nBalance} txs)`);
  console.log(`    ecdh+nonce  ${ecdhS.toFixed(3)}s  ${safeMs(ecdhS, nOut).toFixed(3)} ms/output (${nOut} outputs)`);
  console.log(`    rewind      ${rewindS.toFixed(3)}s  ${safeMs(rewindS, nOut).toFixed(3)} ms/output (${nOut} outputs)`);
  console.log(`    recover-chk ${recheckS.toFixed(3)}s  ${safeMs(recheckS, nOut).toFixed(3)} ms/output (${nOut} outputs)`);
  console.log(`    update      ${updateS.toFixed(4)}s`);

  fs.mkdirSync(outputDir, { recursive: true });
  const csvPath = path.join(outputDir, 'wallet_scan.csv');
  // Column order MUST match benchmark_wallet_scan.py exactly so rows interleave.
  const header = [
    'binding', 'n', 'shielded_outputs', 'total_outputs', 'shielded_inputs', 'total_inputs', 'bits', 'runs',
    'total_s', 'range_verify_s', 'surjection_verify_s', 'balance_verify_s', 'ecdh_s', 'rewind_s',
    'recover_check_s', 'balance_update_s', 'per_tx_total_ms', 'num_range_verifs', 'num_surjection_verifs',
    'num_shielded_outputs', 'per_range_verify_ms', 'per_surjection_verify_ms', 'per_balance_verify_ms',
    'per_ecdh_ms', 'per_rewind_ms', 'per_recover_check_ms',
  ];
  const row = [
    binding, n, m, mPrime, q, qPrime, k, runs,
    totalS, rangeS, surjS, balS, ecdhS, rewindS, recheckS, updateS,
    totalS / n * 1000.0, nRange, nSurj, nOut,
    safeMs(rangeS, nRange), safeMs(surjS, nSurj), safeMs(balS, nBalance),
    safeMs(ecdhS, nOut), safeMs(rewindS, nOut), safeMs(recheckS, nOut),
  ];
  const writeHeader = !fs.existsSync(csvPath);
  if (writeHeader) fs.appendFileSync(csvPath, header.join(',') + '\n');
  fs.appendFileSync(csvPath, row.join(',') + '\n');
  console.log(`\n  ${writeHeader ? 'wrote header + 1 row' : 'appended 1 row'} -> ${csvPath}`);
}

function validate(o) {
  const die = (msg) => { console.error(msg); process.exit(2); };
  if (o.n < 1) die('N must be >= 1');
  if (o.m < 1) die('M (shielded outputs) must be >= 1');
  if (o.mPrime < o.m) die("M' (total outputs) must be >= M");
  if (o.q < 0) die('Q (shielded inputs) must be >= 0');
  if (o.qPrime < o.q) die("Q' (total inputs) must be >= Q");
  if (o.qPrime < 1) die("Q' must be >= 1 (FullShielded outputs need a non-empty surjection domain)");
  if (!(o.k >= 1 && o.k <= 64)) die('k must be in [1, 64] (amounts are u64)');
  if ((1n << BigInt(o.k - 1)) < BigInt(Math.max(o.mPrime, o.qPrime))) {
    die(`k=${o.k} is too small to give every input/output a positive share`);
  }
  if (o.runs < 1) die('--runs must be >= 1');
}

// --------------------------------------------------------------------------
// CLI
// --------------------------------------------------------------------------

function parseArgs(argv) {
  const o = {
    n: DEFAULTS.n, m: DEFAULTS.m, mPrime: DEFAULTS.mPrime, q: DEFAULTS.q, qPrime: DEFAULTS.qPrime,
    k: DEFAULTS.k, runs: 1, binding: 'node-napi',
    outputDir: path.join(__dirname, 'results_wallet'),
  };
  const intFlags = {
    '-N': 'n', '--num-txs': 'n', '-M': 'm', '--shielded-outputs': 'm', '--total-outputs': 'mPrime',
    '-Q': 'q', '--shielded-inputs': 'q', '--total-inputs': 'qPrime', '-k': 'k', '--bits': 'k', '--runs': 'runs',
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (intFlags[a] !== undefined) {
      o[intFlags[a]] = parseInt(argv[++i], 10);
    } else if (a === '--binding') {
      o.binding = argv[++i];
    } else if (a === '--output-dir') {
      o.outputDir = argv[++i];
    } else if (a === '-h' || a === '--help') {
      console.log('Usage: node benchmark_wallet_scan_node.js [-N n] [-M m] [--total-outputs M\'] ' +
        '[-Q q] [--total-inputs Q\'] [-k bits] [--runs r] [--binding label] [--output-dir dir]');
      process.exit(0);
    } else {
      console.error(`unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return o;
}

run(parseArgs(process.argv));
