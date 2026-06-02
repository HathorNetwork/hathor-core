/*
 * Wallet-scan benchmark — WebAssembly binding (@hathor/ct-crypto-wasm).
 *
 * WASM analog of benchmark_wallet_scan.py / benchmark_wallet_scan_node.js. But
 * the wasm build is deliberately NARROW (it is the browser recovery/auditing
 * sibling of the Node addon), so this benchmark can only cover the part of the
 * wallet pass that the wasm module actually implements:
 *
 *   - EXPOSED by @hathor/ct-crypto-wasm (--target web): commitment/generator
 *     construction, deriveEcdhSharedSecret, and the high-level recovery calls
 *     rewindAmountShieldedOutput / rewindFullShieldedOutput.
 *   - NOT EXPOSED: verifyRangeProof, verifySurjectionProof, verifyBalance,
 *     createRangeProof, createSurjectionProof, computeBalancingBlindingFactor,
 *     generateEphemeralKeypair. (Confirmed against src/wasm_bindings.rs.)
 *
 * Consequences:
 *   1. Verification phases (range / surjection / balance) CANNOT run in wasm —
 *      they are left blank in the CSV row (binding=wasm), not zero. A browser
 *      consumer delegates verification to a full node.
 *   2. The wasm build cannot CREATE the rewindable outputs (no createRangeProof),
 *      so the stream is built with @hathor/ct-crypto-node (untimed prep, the same
 *      crate family, so its createShieldedOutputWithBothBlindings produces outputs
 *      that wasm rewindFullShieldedOutput recovers). ONLY recovery is timed, and
 *      it runs in wasm.
 *   3. rewindFullShieldedOutput bundles ECDH + nonce + rewind + token extraction
 *      + the AUDIT-C015 asset-commitment recheck into ONE call (see the wasm
 *      crate's ecdh.rs step 5), so the wasm "rewind_s" is not separable the way
 *      python/node split ecdh_s / rewind_s / recover_check_s. For comparison,
 *      wasm rewind_s ≈ node (ecdh_s + rewind_s + recover_check_s). We do NOT add
 *      a second, external recheck — that would double-count work the bundled call
 *      already did — so recover_check_s and ecdh_s are left blank, matching how
 *      the shielded-outputs-audit browser app consumes this build (it calls
 *      rewindFullShieldedOutput and trusts the result; no external recompute).
 *
 * The recovery phase is the dominant cost of the full scan, so this is still a
 * meaningful cross-binding comparison for the operation that matters most.
 *
 * Requires Node >= 18 with BOTH:
 *   npm install @hathor/ct-crypto-node   (stream construction)
 *   npm install @hathor/ct-crypto-wasm   (timed recovery)
 *
 * Run standalone:  node benchmark_wallet_scan_wasm.js -N 150 -M 1 -k 64 --runs 3
 * or via Python:   benchmark_wallet_scan.py --binding wasm
 *
 * Only N, M, k affect the wasm recovery measurement; M'/Q/Q' are accepted (for
 * launcher parity) and ignored — recovery touches only the M shielded outputs/tx.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let ctNode;
try {
  ctNode = require('@hathor/ct-crypto-node');
} catch (e) {
  console.error('Failed to load @hathor/ct-crypto-node (needed to BUILD the stream; the wasm build\n' +
    'cannot create range proofs). Install it:  npm install @hathor/ct-crypto-node\n' +
    'Underlying error: ' + e.message);
  process.exit(1);
}

const TOKEN_UID = Buffer.alloc(32, 0);          // HTR-like single token
const DEFAULTS = { n: 150, m: 1, k: 64 };

// Dummy wallet scan key (ECDH root secret) — consistent within a run.
const SCAN = ctNode.generateEphemeralKeypair();  // { privateKey, publicKey }

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function randBytes(n) {
  return crypto.randomBytes(n);
}

// A k-bit value in [2^(k-1), 2^k), as BigInt — the range proof exercises ~k bits.
function pickValue(k) {
  const lo = 1n << BigInt(k - 1);
  const hi = (1n << BigInt(k)) - 1n;
  const span = hi - lo + 1n;
  if (span <= 1n) return lo;
  const bits = span.toString(2).length;
  const nbytes = Math.ceil(bits / 8);
  const mask = (1n << BigInt(bits)) - 1n;
  for (;;) {
    let r = 0n;
    const buf = crypto.randomBytes(nbytes);
    for (const byte of buf) r = (r << 8n) | BigInt(byte);
    r = r & mask;
    if (r < span) return lo + r;
  }
}

// --------------------------------------------------------------------------
// Stream construction (NOT timed) — via the Node binding's high-level helper,
// which produces outputs the wasm rewindFullShieldedOutput can recover.
// --------------------------------------------------------------------------

function buildStream(n, m, k) {
  const txs = [];
  for (let i = 0; i < n; i++) {
    const outs = [];
    for (let j = 0; j < m; j++) {
      const value = pickValue(k);
      const vbf = randBytes(32);
      const abf = randBytes(32);
      // createShieldedOutputWithBothBlindings(value, recipientPubkey, tokenUid, vbf, abf)
      // -> { ephemeralPubkey, commitment, rangeProof, assetCommitment, assetBlindingFactor, blindingFactor }
      const o = ctNode.createShieldedOutputWithBothBlindings(value, SCAN.publicKey, TOKEN_UID, vbf, abf);
      outs.push({
        value,
        ephemeralPubkey: o.ephemeralPubkey,
        commitment: o.commitment,
        rangeProof: o.rangeProof,
        assetCommitment: o.assetCommitment,
      });
    }
    txs.push(outs);
  }
  return txs;
}

// --------------------------------------------------------------------------
// Load the wasm module (web target: ESM with an async init(wasmBytes) default).
// --------------------------------------------------------------------------

async function loadWasm() {
  let ns;
  try {
    ns = await import('@hathor/ct-crypto-wasm');
  } catch (e) {
    console.error('Failed to import @hathor/ct-crypto-wasm. Install it:\n' +
      '  npm install @hathor/ct-crypto-wasm   (needs Node >= 18)\n' +
      'Underlying error: ' + e.message);
    process.exit(1);
  }
  // web target: the default export initialises the wasm; feed it the bytes.
  const pkgJson = require.resolve('@hathor/ct-crypto-wasm/package.json');
  const wasmPath = path.join(path.dirname(pkgJson), 'hathor_ct_crypto_wasm_bg.wasm');
  const bytes = fs.readFileSync(wasmPath);
  if (typeof ns.default === 'function') {
    try {
      await ns.default(bytes);                       // older wasm-bindgen: init(BufferSource)
    } catch (e) {
      await ns.default({ module_or_path: bytes });   // newer wasm-bindgen: init({ module_or_path })
    }
  }
  return ns;
}

// --------------------------------------------------------------------------
// Recovery pass (TIMED) — the only wallet work the wasm build supports.
// --------------------------------------------------------------------------

function recoverPass(wasm, txs) {
  const t = { rewind: 0, update: 0, total: 0 };
  const balances = new Map();  // hex(tokenUid) -> BigInt

  const wall0 = process.hrtime.bigint();
  for (const outs of txs) {
    const recovered = [];
    for (const o of outs) {
      // Bundled recovery: ECDH(scanPriv, ephPub) -> nonce -> rewind -> extract
      // (value, token, vbf, abf). rewindFullShieldedOutput ALSO performs the
      // AUDIT-C015 asset-commitment recheck internally (wasm crate ecdh.rs step
      // 5), so there is no separate recheck phase to time — this mirrors how the
      // shielded-outputs-audit app uses the build: call it, trust the result.
      const s = process.hrtime.bigint();
      const rr = wasm.rewindFullShieldedOutput(
        SCAN.privateKey, o.ephemeralPubkey, o.commitment, o.rangeProof, o.assetCommitment);
      t.rewind += Number(process.hrtime.bigint() - s);

      // Cheap sanity check (NOT a timed phase): the rewind already validated the
      // output cryptographically; this only guards the benchmark's stream wiring.
      assert(rr.value === o.value, 'rewound value mismatch');

      recovered.push([Buffer.from(rr.tokenUid).toString('hex'), rr.value]);
    }
    const s = process.hrtime.bigint();
    for (const pair of recovered) {
      balances.set(pair[0], (balances.get(pair[0]) || 0n) + pair[1]);
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

async function run(opts) {
  validate(opts);
  const { n, m, k, runs, binding, outputDir } = opts;
  const wasm = await loadWasm();

  console.log(`Wallet-scan benchmark (WASM) | N=${n} M=${m} k=${k} runs=${runs} binding=${binding}`);
  console.log(`  node=${process.versions.node}  recovery-only (wasm has no verify/create-proof surface); ` +
    `${n * m} FullShielded outputs recovered`);

  const samples = [];
  for (let r = 0; r < runs; r++) {
    const txs = buildStream(n, m, k);          // prep via @hathor/ct-crypto-node: NOT timed
    const res = recoverPass(wasm, txs);        // the timed wasm recovery
    const sec = {};
    for (const key of Object.keys(res.timing)) sec[key] = res.timing[key] / 1e9;
    samples.push(sec);
    console.log(`  run ${r + 1}/${runs}: total=${sec.total.toFixed(3)}s ` +
      `[rewind=${sec.rewind.toFixed(3)} update=${sec.update.toFixed(4)}]`);
  }

  const mean = (key) => samples.reduce((a, s) => a + s[key], 0) / samples.length;
  const totalS = mean('total');
  const rewindS = mean('rewind');
  const updateS = mean('update');
  const nOut = n * m;

  console.log('');
  console.log(`  AVERAGE over ${runs} run(s): total ${totalS.toFixed(3)}s  (${(totalS / n * 1000).toFixed(3)} ms/tx)`);
  console.log('    rewind (bundled: ECDH + rewind + internal AUDIT-C015 recheck)');
  console.log(`                     ${rewindS.toFixed(3)}s  ${safeMs(rewindS, nOut).toFixed(3)} ms/output (${nOut} outputs)`);
  console.log(`    update           ${updateS.toFixed(4)}s`);
  console.log('    (range/surjection/balance verify + a separate ecdh/recover-check phase: '
    + 'not applicable to the wasm build — left blank in CSV)');

  fs.mkdirSync(outputDir, { recursive: true });
  const csvPath = path.join(outputDir, 'wallet_scan.csv');
  // Same column order as benchmark_wallet_scan.py; unsupported phases are blank.
  const header = [
    'binding', 'n', 'shielded_outputs', 'total_outputs', 'shielded_inputs', 'total_inputs', 'bits', 'runs',
    'total_s', 'range_verify_s', 'surjection_verify_s', 'balance_verify_s', 'ecdh_s', 'rewind_s',
    'recover_check_s', 'balance_update_s', 'per_tx_total_ms', 'num_range_verifs', 'num_surjection_verifs',
    'num_shielded_outputs', 'per_range_verify_ms', 'per_surjection_verify_ms', 'per_balance_verify_ms',
    'per_ecdh_ms', 'per_rewind_ms', 'per_recover_check_ms',
  ];
  const E = '';  // blank = "not provided by this binding"
  const row = [
    binding, n, m, m, 0, 0, k, runs,
    totalS, E, E, E, E, rewindS,
    E, updateS, totalS / n * 1000.0, E, E,
    nOut, E, E, E,
    E, safeMs(rewindS, nOut), E,
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
  if (!(o.k >= 1 && o.k <= 64)) die('k must be in [1, 64] (amounts are u64)');
  if (o.runs < 1) die('--runs must be >= 1');
}

// --------------------------------------------------------------------------
// CLI — accepts the full launcher flag set; M'/Q/Q' are ignored (recovery-only).
// --------------------------------------------------------------------------

function parseArgs(argv) {
  const o = {
    n: DEFAULTS.n, m: DEFAULTS.m, k: DEFAULTS.k, runs: 1, binding: 'wasm',
    outputDir: path.join(__dirname, 'results_wallet'),
  };
  const intFlags = {
    '-N': 'n', '--num-txs': 'n', '-M': 'm', '--shielded-outputs': 'm', '-k': 'k', '--bits': 'k', '--runs': 'runs',
  };
  const ignoredValueFlags = { '--total-outputs': 1, '-Q': 1, '--shielded-inputs': 1, '--total-inputs': 1 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (intFlags[a] !== undefined) {
      o[intFlags[a]] = parseInt(argv[++i], 10);
    } else if (ignoredValueFlags[a] !== undefined) {
      i++;  // consume and ignore the value (not meaningful for recovery-only)
    } else if (a === '--binding') {
      o.binding = argv[++i];
    } else if (a === '--output-dir') {
      o.outputDir = argv[++i];
    } else if (a === '-h' || a === '--help') {
      console.log('Usage: node benchmark_wallet_scan_wasm.js [-N n] [-M m] [-k bits] [--runs r] ' +
        '[--binding label] [--output-dir dir]   (M\'/Q/Q\' accepted but ignored)');
      process.exit(0);
    } else {
      console.error(`unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return o;
}

run(parseArgs(process.argv)).catch((e) => {
  console.error(e && e.stack ? e.stack : String(e));
  process.exit(1);
});
