/* 8 Receipts — evidence.

   The only place in the application where a rule run is saved. The old UI had
   three buttons that saved a run and none that explained the difference; this
   screen is the single, deliberate one. */

import { h, fmtTime, shortHash, valueCell } from '../ui/dom.js';
import {
  badge, btn, card, dataTable, emptyBox, field, select, textarea, toast,
  traceView, verdictBox,
} from '../ui/components.js';
import { state, rerender } from '../core/state.js';
import { attempt } from '../core/problems.js';
import { page } from './shared.js';
import * as api from '../core/api.js';

let openRun = null;
let chosen = null;

export function render(route, fresh) {
  if (fresh) {
    loadList();
    if (route.id) open(route.id);
    else if (!state.cache.datasets.length) loadDatasets();
  }

  const setup = card({
    title: 'Save this rule run',
    sub: 'The rule and the dataset are stored by hash, so the receipt proves ' +
      'exactly what was evaluated.',
    body: h('div', {},
      field({
        label: 'Dataset',
        control: select({
          id: 'test-run-dataset',
          value: chosen || '',
          options: [{ value: '', label: 'Select a saved dataset' }].concat(
            state.cache.datasets.map((d) => ({
              value: String(d.id),
              label: d.name + ' \u00b7 ' + d.event_count + ' events',
            })),
          ),
          onChange: (event) => { chosen = event.target.value ? Number(event.target.value) : null; },
        }),
        error: state.cache.datasets.length ? null : 'No datasets yet — create one on the Datasets screen.',
      }),
      h('div', { class: 'row-2' },
        field({
          label: 'Expected verdict',
          control: select({
            id: 'test-run-expected',
            value: '',
            options: [
              { value: '', label: 'No expectation' },
              { value: 'matched', label: 'Matched' },
              { value: 'no_match', label: 'No match' },
              { value: 'not_evaluated', label: 'Could not tell' },
            ],
          }),
        }),
        field({
          label: 'Purpose',
          control: select({
            id: 'test-run-purpose',
            value: 'manual',
            options: [
              { value: 'manual', label: 'Manual check' },
              { value: 'positive', label: 'Positive fixture' },
              { value: 'negative', label: 'Benign / negative fixture' },
              { value: 'regression', label: 'Regression' },
            ],
          }),
        })),
      field({
        label: 'Note',
        control: textarea({
          id: 'test-run-note',
          rows: 3,
          placeholder: 'What question is this run answering?',
        }),
      }),
      btn('Run and save receipt', { kind: 'primary', block: true, id: 'test-run-save', onClick: save })),
    foot: h('span', {}, 'A receipt records the rule hash, dataset hash, verdict, ' +
      'trace and caveats. It does not claim equivalence with the vendor runtime.'),
  });

  const list = card({
    title: 'Recent receipts',
    sub: 'Immutable, newest first.',
    actions: h('div', { class: 'row' },
      h('span', { class: 'badge', id: 'test-run-count', text: String(state.cache.runs.length) }),
      btn('Refresh', { size: 'sm', kind: 'quiet', id: 'test-run-refresh', onClick: loadList })),
    body: listBody(),
  });

  return page('Receipts', {
    eyebrow: 'Verify \u00b7 evidence',
    sub: 'One immutable record per run, with both fingerprints. This is what ' +
      'answers "did we test this, and against what?" six months later.',
    body: h('div', { class: 'datasets-grid' },
      h('div', { class: 'stack' }, setup),
      h('div', { class: 'stack' }, list,
        h('div', { id: 'test-run-result' }, openRun ? runCard(openRun) : emptyBox({
          title: 'Nothing selected',
          body: 'Pick a receipt to read the verdict, the trace and the hashes.',
        }))))});
}

function listBody() {
  if (!state.cache.runs.length) {
    return emptyBox({
      title: 'No receipts yet',
      body: 'Save a run on the left. The first one usually becomes the baseline ' +
        'the rule is judged against.',
    });
  }
  const list = h('div', { class: 'records', id: 'test-run-list' });
  for (const run of state.cache.runs) {
    list.appendChild(h('button', {
      class: 'record' + (openRun && openRun.id === run.id ? ' is-selected' : ''),
      type: 'button',
      on: { click: () => open(run.id) },
    },
      badge(verdictLabel(run.actual_verdict), verdictKind(run.actual_verdict)),
      h('span', { class: 'record-title', text: run.title || run.rule_id || 'Untitled rule' }),
      h('span', { class: 'record-meta', text: '#' + run.id + ' \u00b7 dataset ' + run.dataset_id })));
  }
  return list;
}

function runCard(run) {
  const result = run.result || {};
  const expected = run.expected_verdict;
  return card({
    title: 'Receipt #' + run.id,
    sub: fmtTime(run.created_at) + ' \u00b7 ' + run.purpose +
      (run.note ? ' \u00b7 ' + run.note : ''),
    actions: expected
      ? badge(run.matches_expected ? 'matches expectation' : 'does not match expectation',
        run.matches_expected ? 'ok' : 'danger')
      : badge('no expectation set'),
    body: h('div', { class: 'stack' },
      run.result
        ? verdictBox(result)
        : h('p', { class: 'dim', text: 'This receipt was saved without a stored ' +
          'result, so there is no verdict to show. The hashes below still record ' +
          'what was evaluated.' }),
      expected
        ? h('p', { class: 'dim', text: 'Expected ' + expected + ', got ' +
          (run.actual_verdict || 'nothing') + '.' })
        : null,
      h('div', { class: 'row wrap' },
        badge('rule ' + shortHash(run.rule_hash), null, run.rule_hash),
        badge('dataset ' + shortHash(run.dataset_hash), null, run.dataset_hash),
        badge('evaluator ' + (run.evaluator_version || '\u2014')),
        badge('dataset #' + run.dataset_id)),
      h('h3', { text: 'Stage by stage' }),
      traceView(result),
      rowsTable(result),
      caveats(result))});
}

function rowsTable(result) {
  const rows = (result && result.rows) || [];
  if (!rows.length) return null;
  const columns = [];
  for (const row of rows) for (const key of Object.keys(row)) {
    if (!columns.includes(key)) columns.push(key);
  }
  return h('div', { class: 'stack' },
    h('h3', { text: 'Rows (' + rows.length + ')' }),
    dataTable({
      columns: columns.map((name) => ({ label: name })),
      rows: rows.slice(0, 50).map((row) => columns.map((name) => valueCell(row[name]))),
    }));
}

function caveats(result) {
  const list = (result && result.caveats) || [];
  if (!list.length) return null;
  return h('div', { class: 'stack' },
    h('h3', { text: 'Caveats recorded with this receipt' }),
    ...list.map((caveat) => h('div', {
      class: 'problem', style: { gridTemplateColumns: '92px minmax(0,1fr)' },
    },
      h('span', { class: 'problem-code', text: caveat.code }),
      h('span', { class: 'problem-plain', text: caveat.message }))));
}

const verdictLabel = (verdict) => ({
  matched: 'matched',
  no_match: 'no match',
  not_evaluated: 'could not tell',
}[verdict] || verdict || 'unknown');

const verdictKind = (verdict) => ({
  matched: 'ok',
  no_match: 'caution',
  not_evaluated: null,
}[verdict] || null);

function loadList() {
  attempt(async () => {
    const data = await api.testRuns();
    state.cache.runs = data.test_runs || [];
    if (openRun && !state.cache.runs.some((r) => r.id === openRun.id)) openRun = null;
    rerender();
  }, { context: 'receipts' });
}

function loadDatasets() {
  attempt(async () => {
    const data = await api.datasets('');
    state.cache.datasets = data.datasets || [];
    rerender();
  }, { context: 'receipts' });
}

function open(id) {
  attempt(async () => {
    openRun = await api.testRun(id);
    rerender();
  }, { context: 'receipts' });
}

function save() {
  const datasetId = chosen || Number(
    (document.getElementById('test-run-dataset') || {}).value || 0,
  );
  if (!datasetId) { toast('Choose a dataset first — a run needs evidence.', 'bad'); return; }
  const value = (id) => (document.getElementById(id) || {}).value || '';
  attempt(async () => {
    const data = await api.saveRun({
      payload: state.doc.payload,
      datasetId,
      expectedVerdict: value('test-run-expected'),
      purpose: value('test-run-purpose') || 'manual',
      note: value('test-run-note'),
      ruleEntryId: state.doc.parentId,
    });
    openRun = data;
    state.status.ruleHash = data.rule_hash;
    state.status.datasetHash = data.dataset_hash;
    toast('Receipt ' + data.id + ' saved. The rule and dataset hashes are now ' +
      'linked in history.', data.matches_expected === false ? 'bad' : 'good');
    loadList();
    rerender();
  }, { context: 'receipts' });
}
