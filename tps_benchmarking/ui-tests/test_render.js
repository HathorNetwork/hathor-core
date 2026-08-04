/* Headless check of app.js's result-rendering path.
 *
 * There is no browser on this machine, so a DOM bug in finishRun() shows up only as "the figures
 * didn't appear" — which is how the `tbl.append(el('thead')).lastChild` crash shipped (append()
 * returns undefined). This runs app.js inside a `vm` context with a minimal DOM stub and asserts
 * that both result shapes render, so that class of bug fails here instead of in front of a user.
 *
 *   node test_render.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function makeEl(tag) {
  const node = {
    tagName: tag, children: [], className: '', textContent: '', style: {}, attrs: {},
    append(...kids) { kids.forEach((k) => node.children.push(k)); },          // returns undefined
    appendChild(k) { node.children.push(k); return k; },
    addEventListener() {},
    setAttribute(k, v) { node.attrs[k] = v; },
    scrollIntoView() {},
    classList: {
      _s: new Set(),
      add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      contains(c) { return this._s.has(c); },
      toggle(c, on) { const v = on === undefined ? !this._s.has(c) : !!on; v ? this._s.add(c) : this._s.delete(c); },
    },
    get firstChild() { return node.children[0]; },
    get lastChild() { return node.children[node.children.length - 1]; },
    set innerHTML(v) { if (v === '') node.children.length = 0; },
    get innerHTML() { return ''; },
  };
  return node;
}

const doc = {
  createElement: makeEl,
  createTextNode: (t) => ({ tagName: '#text', textContent: String(t), children: [] }),
  getElementById: () => makeEl('div'),
};

const ctx = {
  document: doc,
  console,
  location: { reload() {} },
  Date,
  Math,
  setInterval: () => 0,
  clearInterval: () => {},
  fetch: () => Promise.reject(new Error('no network in test')),
};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, 'static', 'app.js'), 'utf8'), ctx);

/* walk the stub tree looking for <img> nodes — the thing a user actually misses */
function countImgs(node, seen = new Set()) {
  if (!node || typeof node !== 'object' || seen.has(node)) return 0;
  seen.add(node);
  let n = node.tagName === 'img' ? 1 : 0;
  for (const c of node.children || []) n += countImgs(c, seen);
  return n;
}

function newUi() {
  return {
    runBtn: makeEl('button'), prog: makeEl('div'), bar: makeEl('div'),
    phaseName: makeEl('b'), phaseCount: makeEl('span'),
    results: makeEl('div'), errBox: makeEl('div'),
  };
}

const CASES = {
  scenario: {
    status: 'done',
    result: {
      kind: 'scenario', run_dir: '20260804-000000', scenario: 'P3',
      figures: ['P3/plots/P3_stage_breakdown.png', 'P3/plots/P3_latency_band.png'],
      artifacts: ['P3/plots/P3_stage_breakdown.png', 'results.xlsx', 'summary.md'],
      cells: [
        { label: '1i2o', tps: 124.3, accepted: '30/30', mean_total_us: 8043.1,
          stage_mean_us: { S1: 250.1, S2: 80.2, S3S4: 7100.5, S5: 500.3, S6: 90.4 }, bits: 64 },
        { label: '2i2o', tps: 110.0, accepted: '30/30', mean_total_us: 9090.0,
          stage_mean_us: { S1: 260.0, S2: 82.0, S3S4: 8000.0, S5: 520.0, S6: 95.0 }, bits: 64 },
      ],
    },
  },
  'scenario+segments': {
    status: 'done',
    result: {
      kind: 'scenario', run_dir: '20260804-000001', scenario: 'P11',
      figures: ['P11/plots/P11_transition_T2S.png'],
      artifacts: ['results.xlsx'],
      cells: [{ label: 'T2S-1i2o', tps: 241.0, accepted: '80/80', mean_total_us: 4149.0,
                stage_mean_us: {}, seg_tps: [927.8, 144.3], bits: 64 }],
    },
  },
  custom: {
    status: 'done',
    result: {
      kind: 'custom', run_dir: '20260804-000002',
      figures: ['tps_over_time.png', 'stage_breakdown.png'],
      artifacts: ['tps_over_time.png', 'results.xlsx', 'meta.json'],
      headline: { processing_tps: 884.2, mean_total_us: 1130.0, p99_total_us: 2400.0,
                  accepted: 60, n_measured: 60, rss_peak_mb: 150.2, batch_wall_s: 0.07 },
      stages: [{ stage: 'S3S4', mean_wall_us: 599.2 }],
      cells: [{ label: 'run', tps: 884.2, accepted: '60/60', mean_total_us: 1130.0,
                stage_mean_us: { S3S4: 599.2 } }],
    },
  },
};

let failed = 0;
for (const [name, run] of Object.entries(CASES)) {
  const ui = newUi();
  try {
    ctx.finishRun(ui, run);
    const imgs = countImgs(ui.results);
    const want = run.result.figures.length;
    if (imgs !== want) throw new Error(`rendered ${imgs} <img>, expected ${want}`);
    if (!ui.results.classList.contains('show')) throw new Error('results panel not shown');
    console.log(`  PASS  ${name.padEnd(20)} ${imgs} figure(s), ${run.result.cells.length} cell row(s)`);
  } catch (e) {
    failed++;
    console.log(`  FAIL  ${name.padEnd(20)} ${e.message}`);
  }
}

/* buildCard wiring: every control kind renders, and the console panel exists. */
function findByClass(node, cls, out = [], seen = new Set()) {
  if (!node || typeof node !== 'object' || seen.has(node)) return out;
  seen.add(node);
  if (typeof node.className === 'string' && node.className.split(' ').indexOf(cls) !== -1) out.push(node);
  for (const c of node.children || []) findByClass(c, cls, out, seen);
  return out;
}

const FAKE_SIM = {
  id: 'custom', kind: 'custom', tag: 'FREE', title: 'Custom run', subtitle: 's',
  workload: '1-tip-transparent', cells: 1, description: 'd',
  groups: [
    { label: 'Workload', controls: [
      { kind: 'choice', key: 'workload', label: 'Workload', values: ['a', 'b'], default: 'a',
        help: 'h', wide: true },
      { kind: 'number', key: 'num_txs', label: 'N', min: 1, max: 10, step: 1, default: 5,
        help: 'h', slider: true },
    ] },
    { label: 'Opt', controls: [{ kind: 'bool', key: 'opt_s1', label: 'S1', default: true, help: 'h' }] },
    { label: 'Empty', controls: [] },
  ],
};
try {
  const card = ctx.buildCard(FAKE_SIM, true);
  const checks = [
    ['console panel', findByClass(card, 'console').length === 1],
    ['console body', findByClass(card, 'console-body').length === 1],
    ['wide control', findByClass(card, 'wide').length === 1],
    ['segmented control', findByClass(card, 'seg').length === 1],
    ['toggle chip', findByClass(card, 'chip').length === 1],
    ['progress detail line', findByClass(card, 'phase-where').length === 1],
  ];
  const bad = checks.filter(([, ok]) => !ok).map(([n]) => n);
  if (bad.length) throw new Error(`missing: ${bad.join(', ')}`);
  console.log(`  PASS  ${'buildCard wiring'.padEnd(20)} ${checks.length} elements present`);
} catch (e) {
  failed++;
  console.log(`  FAIL  ${'buildCard wiring'.padEnd(20)} ${e.message}`);
}

/* The progress text is the only thing on screen during a long run, so pin it down exactly. */
const P3 = { kind: 'scenario', tag: 'P3', title: 'Shielded baseline', cells: 1 };
const P8 = { kind: 'scenario', tag: 'P8', title: 'Shielded surjection grid', cells: 9 };
const FREE = { kind: 'custom', tag: 'FREE', title: 'Custom run', cells: 1 };

const PROGRESS_CASES = [
  ['phaseLabel measure', () => ctx.phaseLabel({ phase: 'measure' }), 'Measuring'],
  ['phaseLabel build', () => ctx.phaseLabel({ phase: 'build' }), 'Building transactions'],
  ['detail single cell + reps',
    () => ctx.phaseDetail(P3, { phase: 'measure', cell: '1i2o', cell_index: 0, rep: 2, reps: 3 }),
    'P3 · Shielded baseline   ·   Cell 1i2o   ·   Repetition 2/3'],
  ['detail multi cell + reps',
    () => ctx.phaseDetail(P8, { phase: 'measure', cell: '4i8o', cell_index: 5, rep: 1, reps: 3 }),
    'P8 · Shielded surjection grid   ·   Cell 6/9 (4i8o)   ·   Repetition 1/3'],
  ['detail k=1 hides repetition',
    () => ctx.phaseDetail(P3, { phase: 'measure', cell: '1i2o', cell_index: 0, rep: 1, reps: 1 }),
    'P3 · Shielded baseline   ·   Cell 1i2o'],
  ['detail drops stale cell outside a cell',
    () => ctx.phaseDetail(P8, { phase: 'plot', cell: '8i8o', cell_index: 8, rep: 3, reps: 3 }),
    'P8 · Shielded surjection grid'],
  ['detail custom card stays quiet',
    () => ctx.phaseDetail(FREE, { phase: 'measure', rep: 1, reps: 1 }), ''],
];
for (const [name, fn, want] of PROGRESS_CASES) {
  const got = fn();
  if (got !== want) { failed++; console.log(`  FAIL  ${name.padEnd(20)} got "${got}"  want "${want}"`); }
  else console.log(`  PASS  ${name.padEnd(20)} "${got}"`);
}

console.log(failed ? `\n${failed} FAILED` : '\nall render checks passed');
process.exit(failed ? 1 : 0);
