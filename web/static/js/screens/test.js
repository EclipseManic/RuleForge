/* 6 Test — does it catch what I mean?

   No save button on this screen. A test is a question, not a change: pressing
   Test twice must return the same answer, and saving evidence is a separate,
   deliberate act on the Receipts screen. */

import { h } from '../ui/dom.js';
import {
  badge, btn, card, dataTable, emptyBox, select, textarea, toast, traceView,
  verdictBox,
} from '../ui/components.js';
import { state, mutateQuiet, rerender } from '../core/state.js';
import { attempt } from '../core/problems.js';
import { go } from '../core/router.js';
import { valueCell } from '../ui/dom.js';
import { stepFooter, page } from './shared.js';
import * as api from '../core/api.js';

/* The verdict belongs to the sample it was run against. Remember what that
   was, so an edited sample cannot leave a confident answer on screen. */
let ran = { sample: null, edits: -1, serial: -1 };

export function render(route, fresh) {
  if (fresh && route.query && route.query.get('dataset')) {
    loadDataset(route.query.get('dataset'));
  }

  const sample = state.doc.sample;
  const result = state.status.lastResult;
  /* A verdict belongs to the rule AND the sample it was produced from. Either
     changing makes it an answer to a question nobody asked. */
  const sampleChanged = !!(result && ran.sample !== null && ran.sample !== sample.text);
  const ruleChanged = !!(result && (
    (ran.edits !== -1 && ran.edits !== state.ui.edits) ||
    (ran.serial !== -1 && ran.serial !== state.ui.serial)
  ));
  const stale = sampleChanged || ruleChanged;
  state.status.staleVerdict = stale;
  state.status.staleReason = sampleChanged ? 'sample' : (ruleChanged ? 'rule' : null);

  const inputCard = card({
    title: 'Sample events',
    sub: 'The evidence the verdict is about.',
    actions: badge(result ? 'result below' : 'not run',
      result ? 'ok' : null),
    body: h('div', { class: 'stack' },
      h('div', { class: 'row-2' },
        select({
          id: 'events-format',
          value: sample.format,
          options: [
            { value: 'jsonl', label: 'one JSON object per line' },
            { value: 'json', label: 'a JSON array' },
            { value: 'kv', label: 'key=value' },
            { value: 'syslog', label: 'syslog' },
          ],
          onChange: (event) => {
            mutateQuiet(() => { state.doc.sample.format = event.target.value; });
          },
        })),
      textarea({
        id: 'events',
        rows: 14,
        code: true,
        value: sample.text,
        placeholder: '{"EventID": 4688, "NewProcessName": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"}',
        onInput: (event) => {
          /* The sample is evidence, not the rule: editing it must not claim the
             rule has unsaved changes, and must not invalidate the rendered
             text — only the verdict it was judged against. */
          mutateQuiet(() => { state.doc.sample.text = event.target.value; });
        },
        onKeydown: (event) => {
          if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
            event.preventDefault();
            run();
          }
        },
      }),
      h('div', { class: 'split' },
        h('span', { class: 'field-hint', text: 'Fields must already be parsed. ' +
          'Raw log lines belong on Draft from logs, or in a saved dataset.' }),
        h('div', { class: 'btn-row' },
          btn('Use a dataset \u2192', { size: 'sm', kind: 'quiet', onClick: () => go('datasets') }),
          btn('Test', { kind: 'primary', id: 'run', onClick: run })))),
    foot: h('span', {}, 'Ctrl+Enter runs the test from the sample box.'),
  });

  const resultCard = card({
    title: 'Result',
    sub: state.status.lastVerdict
      ? 'The verdict is about the rule as it was when Test was pressed.'
      : 'Nothing has been run yet.',
    body: h('div', { id: 'evaluation' }, result ? resultBody(result, stale) : emptyBox({
      title: 'No verdict yet',
      body: 'Paste at least one event and press Test. You will get one of three ' +
        'answers: matched, no match, or could not tell.',
      action: btn('What the three verdicts mean', {
        size: 'sm', kind: 'quiet', onClick: () => go('reference'),
      }),
    })),
  });

  return page('Test', {
    eyebrow: 'Step 6 of 6 \u00b7 verify',
    sub: 'Run the rule against events you can read. The sieve shows which stage ' +
      'kept or dropped each row.',
    body: h('div', { class: 'stack-lg' },
      h('div', { class: 'test-grid' }, inputCard, h('div', { class: 'result-stack' }, resultCard)),
      stepFooter('test'))});
}

function resultBody(result, stale) {
  const box = h('div', { class: 'stack' });
  if (stale) {
    const what = state.status.staleReason === 'rule'
      ? 'The rule has changed on another screen since this verdict was produced.'
      : 'The sample has changed since this verdict was produced.';
    box.appendChild(h('div', { class: 'stale-note', text: what +
      ' Press Test again \u2014 this is the answer to the PREVIOUS question, ' +
      'not to the one on this screen.' }));
  }
  box.appendChild(verdictBox(result));

  if (result.refusal) {
    box.appendChild(h('div', { class: 'problem', style: { gridTemplateColumns: '92px minmax(0,1fr)' } },
      h('span', { class: 'problem-code', text: result.refusal.code }),
      h('div', { class: 'problem-plain', text: result.refusal.message })));
  }

  if (result.trace && result.trace.length) {
    box.appendChild(h('h3', { text: 'Stage by stage' }));
    box.appendChild(traceView(result));
  }

  if (result.rows && result.rows.length) {
    const columns = [];
    for (const row of result.rows) {
      for (const key of Object.keys(row)) {
        if (!columns.includes(key)) columns.push(key);
      }
    }
    box.appendChild(h('h3', { text: 'Rows that survived (' + result.rows.length + ')' }));
    box.appendChild(dataTable({
      columns: columns.map((name) => ({ label: name })),
      rows: result.rows.slice(0, 100).map(
        (row) => columns.map((name) => valueCell(row[name])),
      ),
    }));
  }

  if (result.caveats && result.caveats.length) {
    box.appendChild(h('h3', { text: 'Why, and what to be careful about' }));
    for (const caveat of result.caveats) {
      box.appendChild(h('div', {
        class: 'problem',
        style: { gridTemplateColumns: '92px minmax(0,1fr)' },
      },
        h('span', { class: 'problem-code', text: caveat.code }),
        h('div', {},
          h('div', { class: 'problem-plain', text: caveat.message }),
          caveat.verified === false
            ? h('div', { class: 'problem-engine', text:
              'inferred from the rule, not measured against your sample' })
            : null)));
    }
  }

  if (result.rows && result.rows.length) {
    box.appendChild(h('div', { class: 'split' },
      h('span', { class: 'muted', text: 'Keep this result as evidence?' }),
      btn('Save a receipt \u2192', { size: 'sm', onClick: () => go('receipts') })));
  }
  return box;
}

function run() {
  const sample = state.doc.sample;
  if (!sample.text.trim()) {
    toast('Paste at least one event to test against.', 'bad');
    return;
  }
  attempt(async () => {
    const result = await api.evaluate(state.doc.payload, sample.text, sample.format);
    state.status.lastResult = result;
    state.status.lastVerdict = result.verdict;
    ran = { sample: sample.text, edits: state.ui.edits, serial: state.ui.serial };
    rerender();
  }, { context: 'test' });
}

function loadDataset(id) {
  attempt(async () => {
    const data = await api.dataset(id);
    mutateQuiet(() => {
      state.doc.sample.text = JSON.stringify(data.events || [], null, 2);
      state.doc.sample.format = 'json';
      state.status.datasetHash = data.content_hash;
    });
    rerender();
  }, { context: 'test' });
}
