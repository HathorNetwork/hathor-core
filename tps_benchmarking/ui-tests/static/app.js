/* Renders every simulation card from /api/simulations — no per-flag HTML is hand-written, so
   adding a scenario to simulations.py makes it appear here automatically.
   Runs are started via POST /api/run and polled at 400ms until done|error. */
'use strict';

const el = (tag, cls, txt) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (txt !== undefined) n.textContent = txt;
  return n;
};
const fmt = (v, d = 0) =>
  v === null || v === undefined || Number.isNaN(v) ? '—'
    : v.toLocaleString(undefined, { minimumFractionDigits: d, maximumFractionDigits: d });

/* ---------- controls ---------- */

function numberControl(c, state, resets) {
  const wrap = el('div', 'ctl');
  const id = `f-${c.key}-${Math.random().toString(36).slice(2, 7)}`;
  const label = el('label', 'name', c.label);
  label.htmlFor = id;
  wrap.append(label);

  const row = el('div', 'row');
  const num = el('input');
  Object.assign(num, { type: 'number', id, min: c.min, max: c.max, step: c.step, value: c.default });
  row.append(num);

  let slider = null;
  if (c.slider) {
    slider = el('input');
    Object.assign(slider, { type: 'range', min: c.min, max: c.max, step: c.step, value: c.default });
    slider.setAttribute('aria-label', `${c.label} slider`);
    row.append(slider);
  }
  wrap.append(row);
  if (c.help) wrap.append(el('div', 'help', c.help));

  const clamp = (v) => Math.min(c.max, Math.max(c.min, Number.isFinite(v) ? v : c.default));
  const commit = (v, echoNum) => {
    state[c.key] = v;
    if (slider) slider.value = v;
    if (echoNum) num.value = v;
  };
  // The number box is authoritative while typing (clamping mid-keystroke fights the user);
  // it is normalised on blur, whereas the slider commits live.
  num.addEventListener('input', () => {
    const v = parseFloat(num.value);
    if (Number.isFinite(v)) commit(clamp(v), false);
  });
  num.addEventListener('blur', () => commit(clamp(parseFloat(num.value)), true));
  if (slider) slider.addEventListener('input', () => commit(clamp(parseFloat(slider.value)), true));

  state[c.key] = c.default;
  resets.push(() => commit(c.default, true));
  return wrap;
}

function choiceControl(c, state, resets) {
  const wrap = el('div', 'ctl' + (c.wide ? ' wide' : ''));
  wrap.append(el('label', 'name', c.label));
  const seg = el('div', 'seg');
  const btns = c.values.map((v) => {
    const b = el('button', 'seg-btn', String(v));
    b.type = 'button';
    b.addEventListener('click', () => set(v));
    seg.append(b);
    return b;
  });
  const set = (v) => {
    state[c.key] = v;
    btns.forEach((b, i) => b.classList.toggle('on', c.values[i] === v));
  };
  wrap.append(seg);
  if (c.help) wrap.append(el('div', 'help', c.help));
  set(c.default);
  resets.push(() => set(c.default));
  return wrap;
}

function boolControl(c, state, resets) {
  const chip = el('label', 'chip' + (c.default ? ' on' : ''));
  const box = el('input');
  box.type = 'checkbox';
  box.checked = c.default;
  const body = el('span', 'chip-label');
  body.append(document.createTextNode(c.label));
  if (c.help) { body.append(el('br')); body.append(el('small', null, c.help)); }
  chip.append(box, el('span', 'dot'), body);
  const set = (v) => {
    box.checked = v;
    state[c.key] = v;
    chip.classList.toggle('on', v);
  };
  box.addEventListener('change', () => set(box.checked));
  state[c.key] = c.default;
  resets.push(() => set(c.default));
  return chip;
}

/* ---------- card ---------- */

function buildCard(sim, startOpen) {
  const state = {};
  const resets = [];          // per-control restore fns, so Reset never reloads the page
  const card = el('section', `sim ${sim.kind}`);
  card.setAttribute('open-state', startOpen ? 'open' : 'closed');

  const head = el('button', 'sim-head');
  head.type = 'button';
  head.setAttribute('aria-expanded', String(!!startOpen));
  const titles = el('div');
  titles.append(el('div', 'sim-title', sim.title), el('div', 'sim-sub', sim.subtitle));
  head.append(el('span', 'chev', '▶'), el('span', 'sim-tag', sim.tag), titles);
  head.addEventListener('click', () => {
    const open = card.getAttribute('open-state') === 'open';
    card.setAttribute('open-state', open ? 'closed' : 'open');
    head.setAttribute('aria-expanded', String(!open));
  });

  const body = el('div', 'sim-body');
  body.append(el('p', 'sim-desc', sim.description));

  for (const g of sim.groups) {
    const grp = el('div', 'group');
    grp.append(el('div', 'group-label', g.label));
    if (g.note) grp.append(el('div', 'group-note', g.note));
    const bools = g.controls.length > 0 && g.controls.every((c) => c.kind === 'bool');
    const box = el('div', bools ? 'flags' : 'controls');
    const build = { bool: boolControl, choice: choiceControl, number: numberControl };
    for (const c of g.controls) box.append((build[c.kind] || numberControl)(c, state, resets));
    grp.append(box);
    body.append(grp);
  }

  const runBtn = el('button', 'btn', 'Simulate');
  const resetBtn = el('button', 'btn ghost', 'Reset');
  const est = el('span', 'est', '');
  const actions = el('div', 'actions');
  actions.append(runBtn, resetBtn, est);

  const prog = el('div', 'progress');
  const bar = el('div', 'bar');
  bar.append(el('i'));
  const phase = el('div', 'phase');
  const phaseName = el('b', null, '');
  const phaseCount = el('span', null, '');
  phase.append(phaseName, phaseCount);
  const phaseWhere = el('div', 'phase-where', '');
  prog.append(bar, phase, phaseWhere);

  // Node output console — the worker's own stdout/stderr, streamed incrementally.
  const con = el('div', 'console');
  const conHead = el('button', 'console-head');
  conHead.type = 'button';
  const conChev = el('span', 'chev', '▶');
  const conCount = el('span', 'console-meta', '');
  conHead.append(conChev, document.createTextNode('Node output'), conCount);
  const conBody = el('pre', 'console-body');
  conHead.addEventListener('click', () => {
    const open = con.classList.contains('open');
    con.classList.toggle('open', !open);
    conHead.setAttribute('aria-expanded', String(!open));
    if (!open) conBody.scrollTop = conBody.scrollHeight;
  });
  con.append(conHead, conBody);

  const results = el('div', 'results');
  const errBox = el('div', 'error');

  body.append(actions, prog, con, results, errBox);
  card.append(head, body);

  // Cost estimate. Cells x reps is what actually drives the wall clock, and the shielded
  // scenarios are orders of magnitude slower per tx, so warn rather than let someone start a
  // multi-hour run by accident.
  const setEst = () => {
    const per = (state.num_txs || 0) + (state.warmup_txs || 0);
    const runs = sim.cells * (state.k || 1);
    const total = per * runs;
    const shielded = /shielded|multibatch/.test(sim.workload);
    let txt = `${fmt(sim.cells)} cell${sim.cells === 1 ? '' : 's'} × ${state.k || 1} rep`
            + `${(state.k || 1) === 1 ? '' : 's'} = ${fmt(runs)} run${runs === 1 ? '' : 's'}`
            + `, ${fmt(total)} transactions total`;
    est.classList.toggle('warn', shielded && total > 4000);
    if (shielded && total > 4000) txt += ' — shielded, expect many minutes';
    est.textContent = txt;
  };
  setEst();
  body.addEventListener('input', setEst);
  body.addEventListener('change', setEst);

  resetBtn.addEventListener('click', () => {
    resets.forEach((fn) => fn());
    results.classList.remove('show');
    errBox.classList.remove('show');
    setEst();
  });
  runBtn.addEventListener('click', () =>
    startRun(sim, state, { runBtn, prog, bar, phaseName, phaseCount, phaseWhere, results, errBox,
                           con, conBody, conCount }));

  return card;
}

/* ---------- node output console ---------- */

/* Pulls only what it hasn't seen (?since=), appends, and keeps the view pinned to the bottom
   unless the user has scrolled up to read something. */
function makeLogPump(ui, runId) {
  let since = 0;
  let lines = 0;
  ui.conBody.textContent = '';
  ui.conCount.textContent = 'waiting…';
  return async function pull() {
    let d;
    try {
      d = await (await fetch(`/api/run/${runId}/log?since=${since}`)).json();
    } catch {
      return;                                    // transient; next tick retries
    }
    if (d.error) return;
    if (d.missed > 0 && since > 0) {
      ui.conBody.append(document.createTextNode(`… ${d.missed} earlier line(s) dropped …\n`));
    }
    if (d.lines && d.lines.length) {
      const atBottom = ui.conBody.scrollHeight - ui.conBody.scrollTop - ui.conBody.clientHeight < 40;
      ui.conBody.append(document.createTextNode(d.lines.join('\n') + '\n'));
      lines += d.lines.length;
      if (atBottom) ui.conBody.scrollTop = ui.conBody.scrollHeight;
    }
    since = d.next;
    ui.conCount.textContent = lines
      ? `${fmt(lines)} line${lines === 1 ? '' : 's'}`
      : (d.running ? 'quiet — node debug logging is suppressed' : 'no output');
  };
}

/* ---------- run lifecycle ---------- */

const PHASE_TEXT = {
  boot: 'Starting node', build: 'Building transactions', warmup: 'Warming up',
  measure: 'Measuring', analyse: 'Reducing timings', plot: 'Rendering figures',
  export: 'Writing results.xlsx', cell: 'Starting cell', done: 'Complete', error: 'Failed',
};

function phaseLabel(run) {
  return PHASE_TEXT[run.phase] || run.message || run.phase;
}

/* Phases that happen INSIDE a cell. Outside them (plot, export) the cell/repetition counters are
   stale, so the detail line drops them rather than showing a finished cell as if it were running. */
const IN_CELL = ['cell', 'build', 'warmup', 'measure'];

/* The "where am I" line under the bar:
   "P3 · Shielded baseline   ·   Cell 1/1 (1i2o)   ·   Repetition 2/3" */
function phaseDetail(sim, run) {
  const bits = [];
  if (sim.kind === 'scenario') bits.push(`${sim.tag} · ${sim.title}`);
  if (IN_CELL.indexOf(run.phase) !== -1) {
    if (run.cell) {
      bits.push(sim.cells > 1
        ? `Cell ${(run.cell_index || 0) + 1}/${sim.cells} (${run.cell})`
        : `Cell ${run.cell}`);
    }
    if (run.reps > 1) bits.push(`Repetition ${run.rep}/${run.reps}`);
  }
  return bits.join('   ·   ');
}

async function startRun(sim, state, ui) {
  const { runBtn, prog, bar, phaseName, phaseCount, phaseWhere, results, errBox, con } = ui;
  runBtn.disabled = true;
  runBtn.textContent = 'Running…';
  results.classList.remove('show');
  errBox.classList.remove('show');
  prog.classList.add('show');
  bar.classList.add('indet');
  bar.firstChild.style.width = '0%';
  phaseName.textContent = 'Starting…';
  phaseCount.textContent = '';
  // Say what is about to run before the first poll comes back, so the panel is never blank.
  phaseWhere.textContent = phaseDetail(sim, { phase: 'cell', reps: state.k || 1, rep: 1 });

  let runId;
  try {
    const res = await fetch('/api/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sim_id: sim.id, params: state }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    runId = data.run_id;
  } catch (e) {
    return failRun(ui, `Could not start the run: ${e.message}`, '');
  }

  con.classList.add('show');
  const pullLog = makeLogPump(ui, runId);
  pullLog();

  const poll = setInterval(async () => {
    pullLog();
    let run;
    try {
      run = await (await fetch(`/api/run/${runId}`)).json();
    } catch {
      return; // transient; keep polling
    }
    phaseName.textContent = phaseLabel(run);
    phaseWhere.textContent = phaseDetail(sim, run);
    if (run.total > 0) {
      bar.classList.remove('indet');
      bar.firstChild.style.width = `${(run.done / run.total) * 100}%`;
      phaseCount.textContent = `${fmt(run.done)} / ${fmt(run.total)} tx`;
    } else {
      bar.classList.add('indet');
      phaseCount.textContent = run.message || '';
    }
    if (run.status === 'done') {
      clearInterval(poll);
      pullLog();                                   // flush whatever arrived after the last tick
      // A render bug must not look like "the run produced nothing" — the artifacts are on disk
      // either way, so surface the failure instead of leaving the panel silently empty.
      try {
        finishRun(ui, run);
      } catch (e) {
        failRun(ui, `Run finished, but rendering the results failed: ${e.message}. `
                  + `The files are still in ui-tests/runs/${(run.result || {}).run_dir || ''}/`,
                e.stack || '');
      }
    } else if (run.status === 'error') {
      clearInterval(poll);
      pullLog();                                   // flush whatever arrived after the last tick
      failRun(ui, run.message, run.trace);
    }
  }, 400);
}

function failRun(ui, msg, trace) {
  ui.prog.classList.remove('show');
  ui.runBtn.disabled = false;
  ui.runBtn.textContent = 'Simulate';
  ui.errBox.innerHTML = '';
  ui.errBox.append(el('b', null, 'Run failed — '), document.createTextNode(msg || 'unknown error'));
  if (trace) ui.errBox.append(el('pre', null, trace));
  ui.errBox.classList.add('show');
}

function finishRun(ui, run) {
  const { results, prog, runBtn } = ui;
  prog.classList.remove('show');
  runBtn.disabled = false;
  runBtn.textContent = 'Simulate again';

  const r = run.result;
  results.innerHTML = '';

  const tile = (k, v, u, hero) => {
    const t = el('div', 'tile' + (hero ? ' hero' : ''));
    const val = el('div', 'v');
    val.append(document.createTextNode(v));
    if (u) val.append(el('span', 'u', u));
    t.append(el('div', 'k', k), val);
    return t;
  };

  if (r.kind === 'custom') {
    const h = r.headline;
    const tiles = el('div', 'tiles');
    tiles.append(
      tile('Throughput', fmt(h.processing_tps), 'tx/s', true),
      tile('Mean per tx', fmt(h.mean_total_us), 'µs'),
      tile('p99 per tx', fmt(h.p99_total_us), 'µs'),
      tile('Accepted', `${fmt(h.accepted)}/${fmt(h.n_measured)}`, ''),
      tile('Peak RSS', fmt(h.rss_peak_mb, 1), 'MB'),
      tile('Wall clock', fmt(h.batch_wall_s, 2), 's'),
    );
    results.append(tiles);
  } else {
    // Scenario: the comparison BETWEEN cells is the result, so lead with the table.
    const best = r.cells.reduce((a, c) => Math.max(a, c.tps), 0);
    const tbl = el('table', 'cells');
    const head = el('tr');
    ['Cell', 'tx/s', 'Accepted', 'Mean µs/tx', 'verify', 'cons.', 'post-cons.'].forEach((h, i) => {
      const th = el('th', i ? 'num' : null, h);
      head.append(th);
    });
    const thead = el('thead');          // NB: Element.append() returns undefined — never chain off it
    thead.append(head);
    tbl.append(thead);
    const tb = el('tbody');
    for (const c of r.cells) {
      const tr = el('tr');
      tr.append(el('td', null, c.label));
      const tps = el('td', 'num tps');
      tps.append(el('span', 'barcell'), document.createTextNode(fmt(c.tps)));
      tps.firstChild.style.width = `${best ? (c.tps / best) * 100 : 0}%`;
      tr.append(tps);
      tr.append(el('td', 'num', c.accepted));
      tr.append(el('td', 'num', fmt(c.mean_total_us)));
      const sm = c.stage_mean_us || {};
      ['S3S4', 'S5', 'S6'].forEach((s) => tr.append(el('td', 'num', sm[s] ? fmt(sm[s]) : '—')));
      tb.append(tr);
    }
    tbl.append(tb);
    results.append(tbl);
    if (r.cells.some((c) => c.seg_tps)) {
      const segs = r.cells.filter((c) => c.seg_tps)
        .map((c) => `${c.label}: ${c.seg_tps.map((v) => fmt(v)).join(' → ')} tx/s`);
      results.append(el('p', 'segnote', `Segment throughput — ${segs.join('   ·   ')}`));
    }
  }

  // Report figures are light-themed (they are the report's own); give them a light surface so
  // they read as intentional rather than broken against the dark UI.
  const figs = el('div', 'figs' + (r.kind === 'scenario' ? ' light' : ''));
  for (const f of r.figures) {
    const fig = el('figure');
    const img = el('img');
    img.src = `/runs/${r.run_dir}/${f}?t=${Date.now()}`;
    img.alt = f.split('/').pop().replace(/[_-]/g, ' ').replace('.png', '');
    img.loading = 'lazy';
    fig.append(img, el('figcaption', null, f.split('/').pop().replace('.png', '')));
    figs.append(fig);
  }
  results.append(figs);

  const files = el('div', 'files');
  for (const a of r.artifacts) {
    const link = el('a', null, a.split('/').pop());
    link.href = `/runs/${r.run_dir}/${a}`;
    link.download = a.split('/').pop();
    files.append(link);
  }
  files.append(el('span', 'where', `ui-tests/runs/${r.run_dir}/`));
  results.append(files);
  results.classList.add('show');
  results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* ---------- boot ---------- */

(async () => {
  const host = document.getElementById('sims');
  try {
    const { simulations } = await (await fetch('/api/simulations')).json();
    host.innerHTML = '';
    let scenariosStarted = false;
    simulations.forEach((s, i) => {
      if (s.kind === 'scenario' && !scenariosStarted) {
        scenariosStarted = true;
        const h = el('div', 'section-head');
        h.append(el('h2', null, 'Report scenarios'),
                 el('p', null, 'P1–P12 from the benchmark report. Each runs its cells on fresh '
                             + 'nodes and renders the report’s own figures.'));
        host.append(h);
      }
      host.append(buildCard(s, i === 0));   // only the first card starts open
    });
  } catch (e) {
    host.innerHTML = '';
    host.append(el('p', 'loading', `Could not load simulations: ${e.message}`));
  }
})();
