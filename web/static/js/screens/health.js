/* Health — is anything broken, right now?

   The point is not a green tick. It is that a failed check names the exact
   path, the exact status and the command that reproduces it, so a broken
   install is diagnosable without reading the source. */

import { h } from '../ui/dom.js';
import { badge, btn, card, codeBlock } from '../ui/components.js';
import { state, rerender } from '../core/state.js';
import { attempt } from '../core/problems.js';
import { page } from './shared.js';
import * as api from '../core/api.js';

let rows = [];
let running = false;
let selfTest = null;
let storeCounts = null;

const RULE = [
  '// title: Health check rule',
  'SecurityEvent',
  '| where EventID == 4624',
].join('\n');

const SAMPLE = '{"EventID": 4624, "Computer": "HEALTH", "TimeGenerated": 1767182400}';

export function render(route, fresh) {
  if (fresh && !rows.length && !running) runChecks();

  return page('Health', {
    eyebrow: 'Reference \u00b7 diagnostics',
    sub: 'Every read endpoint, the whole rule path end to end, and the counts in ' +
      'the local store. Run it first when something looks wrong.',
    actions: btn(running ? 'Running\u2026' : 'Run the checks', {
      kind: 'primary', disabled: running, onClick: () => runChecks(true),
    }),
    body: h('div', { class: 'stack-lg' },
      checkCard(),
      selfTestCard(),
      storeCard(),
      reproduceCard())});
}

function checkCard() {
  const box = h('div', { class: 'stack' });
  if (!rows.length) {
    box.appendChild(h('p', { class: 'muted', text: running ? 'Running\u2026' : 'No checks run yet.' }));
  } else {
    for (const row of rows) {
      box.appendChild(h('div', { class: 'health-row' },
        h('span', { class: 'dot' + (row.state === 'ok' ? ' dot--ok'
          : row.state === 'skipped' ? '' : ' dot--bad'),
        title: row.state }),
        h('span', { class: 'health-name', text: row.name, title: row.detail || row.name }),
        h('span', { class: 'health-note', text: row.note || '' }),
        h('span', { class: 'health-ms', text: row.ms === null ? '\u2014' : row.ms + ' ms' })));
    }
  }
  return card({
    title: 'Endpoints',
    sub: rows.length
      ? rows.filter((r) => r.state === 'ok').length + ' of ' +
        rows.filter((r) => r.state !== 'skipped').length + ' responding'
      : '',
    body: box,
    foot: h('span', {}, 'Checks that would write to your store are listed as ' +
      'skipped rather than run against live data.'),
  });
}

function selfTestCard() {
  return card({
    title: 'End-to-end self test',
    sub: 'Lower a known rule, render it, evaluate it against a known event, and ' +
      'expect "matched". This is the shortest path that proves the whole chain works.',
    body: selfTest ? selfTestBody() : h('p', { class: 'muted', text: 'Not run yet.' }),
  });
}

function selfTestBody() {
  const steps = selfTest.steps;
  return h('div', { class: 'stack' },
    h('div', { class: 'row wrap' },
      badge(selfTest.ok ? 'passed' : 'failed', selfTest.ok ? 'ok' : 'danger'),
      badge('verdict ' + selfTest.verdict, selfTest.verdict === 'matched' ? 'ok' : 'caution')),
    h('div', { class: 'trace' },
      ...steps.map((step) => h('div', { class: 'trace-row' },
        h('span', { class: 'trace-name', text: step.name }),
        h('span', { class: 'trace-kind', text: step.ok ? 'ok' : 'fail' }),
        h('span', { class: 'health-note', text: step.note || '' }),
        h('span', { class: 'trace-counts', text: step.ms + ' ms' })))),
    selfTest.verdict !== 'matched'
      ? h('p', { class: 'problem-plain', text:
        'Expected "matched" from EventID == 4624 against {"EventID": 4624}. A ' +
        'different verdict means the evaluate path changed, not that your rule is wrong.' })
      : null);
}

function storeCard() {
  const counts = storeCounts;
  return card({
    title: 'What is stored locally',
    body: counts
      ? h('div', { class: 'row wrap' },
        badge(counts.datasets + ' datasets', 'info'),
        badge(counts.runs + ' receipts', 'info'),
        badge(counts.versions + ' versions', 'info'),
        h('span', { class: 'muted', text: 'in data/history.sqlite3' }))
      : h('p', { class: 'muted', text: 'Loading counts\u2026' }),
  });
}

function reproduceCard() {
  return card({
    title: 'Reproduce any of this by hand',
    body: codeBlock({
      label: 'the same calls, from a terminal',
      copy: true,
      text: [
        '# start the workbench',
        'python run.py',
        '',
        '# does the server answer at all',
        'curl -s http://127.0.0.1:8765/api/health',
        '',
        '# the whole engine suite, then the corpus sweep',
        'python run.py verify',
        '',
        '# one raw request, exactly as the page sends it',
        "curl -s -X POST http://127.0.0.1:8765/api/render \\",
        "  -H 'Content-Type: application/json' \\",
        "  -d '{\"dialect\": \"splunk\", \"rule\": {\"schema\": 1, \"rule\": {}}}'",
      ].join('\n'),
    }),
    foot: h('span', {}, 'The second command proves the engine; the first proves ' +
      'the page can reach it. When the UI looks wrong, knowing which of those ' +
      'two broke is most of the diagnosis.'),
  });
}

async function timed(name, fn) {
  const started = performance.now();
  try {
    const detail = await fn();
    return {
      name, state: 'ok', ms: Math.round(performance.now() - started),
      note: detail || '', detail: detail || '',
    };
  } catch (err) {
    return {
      name, state: 'failed', ms: Math.round(performance.now() - started),
      note: (err.code || 'ERROR') + ' \u2014 ' + err.message,
      detail: err.message,
    };
  }
}

async function runChecks(explicit) {
  if (running) return;
  running = true;
  rows = [];
  selfTest = null;
  if (explicit) rerender();

  const payload = (await attempt(() => api.lower('sentinel', RULE, 'health'),
    { context: 'health' })) || null;

  const checks = [
    ['GET /api/health', async () => (await api.health()).ok ? 'ok: true' : 'unexpected body'],
    ['GET /api/dialects', async () => {
      const data = await api.dialects();
      return data.dialects.length + ' dialects, ' +
        data.dialects.filter((d) => d.status === 'ready').length + ' ready';
    }],
    ['GET /api/datasets', async () => (await api.datasets('')).datasets.length + ' rows'],
    ['GET /api/test-runs', async () => (await api.testRuns()).test_runs.length + ' rows'],
    ['GET /api/history', async () => (await api.history({ limit: 1 })).entries.length + ' rows'],
    ['POST /api/lower', async () => payload
      ? 'parsed, ' + (payload.diagnostics || []).length + ' diagnostic(s)'
      : 'parsed'],
    ['POST /api/outline', async () => payload
      ? ((await api.outline(payload.rule)).outline ? 'outline returned' : 'no outline')
      : 'skipped: lower failed'],
    ['POST /api/render', async () => payload
      ? (await api.render('sentinel', payload.rule)).text.length + ' chars'
      : 'skipped: lower failed'],
    ['POST /api/validate', async () => payload
      ? ((await api.validate(payload.rule)).ok ? 'valid' : 'not valid')
      : 'skipped: lower failed'],
    ['POST /api/evaluate', async () => payload
      ? (await api.evaluate(payload.rule, SAMPLE, 'jsonl')).verdict
      : 'skipped: lower failed'],
    ['POST /api/synthesize', async () => {
      const data = await api.synthesize(SAMPLE + '\n' + SAMPLE.replace('HEALTH', 'HEALTH2'),
        'jsonl', {});
      return data.samples + ' samples, ' + (data.fields || []).length + ' fields';
    }],
  ];

  for (const [name, fn] of checks) {
    rows.push(await timed(name, fn));
    rerender();
    void explicit;
  }

  /* The three write endpoints are listed, not probed: running them would put
   test rows in the user's store, which is exactly the kind of side effect a
   health check must not have. */
  for (const name of ['POST /api/datasets', 'POST /api/history', 'POST /api/test-runs']) {
    rows.push({
      name, state: 'skipped', ms: null,
      note: 'not run: this endpoint writes to your store',
    });
  }

  selfTest = await runSelfTest(payload);
  const counts = await attempt(async () => ({
    datasets: (await api.datasets('')).datasets.length,
    runs: (await api.testRuns()).test_runs.length,
    versions: (await api.history({ limit: 1 })).total || 0,
  }), { context: 'health' });
  storeCounts = counts;
  /* The dot means "the whole chain works", so a failed self test has to turn it
     red even when every endpoint answered. It used to follow the endpoints
     only, which meant a green dot beside a failed end-to-end run. */
  state.status.health = rows.every((r) => r.state !== 'failed')
    && !(selfTest && selfTest.ok === false);
  running = false;
  rerender();
}

async function runSelfTest(lowered) {
  const steps = [];
  const step = async (name, fn) => {
    const started = performance.now();
    try {
      const note = await fn();
      steps.push({ name, ok: true, note: note || '', ms: Math.round(performance.now() - started) });
    } catch (err) {
      steps.push({
        name, ok: false, note: (err.code || 'ERROR') + ' \u2014 ' + err.message,
        ms: Math.round(performance.now() - started),
      });
    }
  };

  let rulePayload = null;
  await step('lower a known rule', async () => {
    if (!lowered) throw new Error('lower failed above');
    rulePayload = lowered.rule;
    return 'parsed';
  });
  await step('render it for Sentinel', async () => {
    const data = await api.render('sentinel', rulePayload);
    return data.text.split('\n')[0];
  });
  let verdict = null;
  await step('evaluate one known event', async () => {
    const result = await api.evaluate(rulePayload, SAMPLE, 'jsonl');
    verdict = result.verdict;
    return result.verdict;
  });

  return {
    ok: steps.every((s) => s.ok) && verdict === 'matched',
    verdict: verdict || 'not run',
    steps,
  };
}
