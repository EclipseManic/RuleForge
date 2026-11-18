/* 11 Draft from logs — guess a rule, and show the reasoning.

   The interesting half is not the proposed rule; it is the field table saying
   which fields were steady enough to pin and which only looked steady. A field
   constant in three samples is not necessarily constant in production, so the
   output is labelled a hypothesis. */

import { h } from '../ui/dom.js';
import {
  badge, btn, card, checkbox, dataTable, emptyBox, field, input, select,
  textarea, toast,
} from '../ui/components.js';
import { state, loadRule, rerender } from '../core/state.js';
import { attempt } from '../core/problems.js';
import { go } from '../core/router.js';
import { linesOf } from '../core/ir.js';
import { page } from './shared.js';
import * as api from '../core/api.js';

const form = {
  format: 'jsonl',
  text: '',
  table: '',
  skipVolatile: true,
  skipTimestamps: true,
  threshold: false,
  groupBy: '',
};
let outcome = null;

export function render() {
  const options = card({
    title: 'Samples',
    body: h('div', { class: 'stack' },
      field({
        label: 'Format',
        control: select({
          id: 'log-format',
          value: form.format,
          options: [
            { value: 'jsonl', label: 'JSON, one object per line' },
            { value: 'json', label: 'JSON array' },
            { value: 'kv', label: 'key=value pairs' },
            { value: 'syslog', label: 'Syslog with key=value body' },
          ],
          onChange: (event) => { form.format = event.target.value; },
        }),
      }),
      field({
        label: 'Log lines',
        control: textarea({
          id: 'log-text',
          rows: 12,
          code: true,
          value: form.text,
          placeholder: '{"EventID": 4624, "Computer": "HOST1", "ProcessId": 4821}\n{"EventID": 4624, "Computer": "HOST2", "ProcessId": 9134}',
          onInput: (event) => { form.text = event.target.value; },
        }),
        hint: 'Two or more events of the same kind. One event cannot tell a ' +
          'stable field from a volatile one.',
      })),
  });

  const tuning = card({
    title: 'What to pin',
    body: h('div', { class: 'stack' },
      field({
        label: 'Table or index',
        control: input({
          id: 'log-table',
          value: form.table,
          placeholder: 'SecurityEvent',
          onInput: (event) => { form.table = event.target.value; },
        }),
      }),
      checkbox({
        id: 'opt-skip-volatile',
        checked: form.skipVolatile,
        label: 'Skip fields that differ between samples',
        onChange: (event) => { form.skipVolatile = event.target.checked; },
      }),
      checkbox({
        id: 'opt-skip-timestamps',
        checked: form.skipTimestamps,
        label: 'Skip timestamps and identifiers',
        onChange: (event) => { form.skipTimestamps = event.target.checked; },
      }),
      checkbox({
        id: 'opt-threshold',
        checked: form.threshold,
        label: 'Add a count threshold',
        onChange: (event) => { form.threshold = event.target.checked; },
      }),
      field({
        label: 'Group by',
        control: input({
          id: 'opt-groupby',
          value: form.groupBy,
          placeholder: 'Computer, Account',
          onInput: (event) => { form.groupBy = event.target.value; },
        }),
        hint: 'Comma-separated. Only used when a count threshold is added.',
      }),
      btn('Propose a rule', { kind: 'primary', block: true, id: 'log-go', onClick: propose })),
  });

  return page('Draft from logs', {
    eyebrow: 'Derive \u00b7 from samples',
    sub: 'See which fields are actually stable before deciding what the rule ' +
      'should match. The proposal is a hypothesis, not a detection.',
    body: h('div', { class: 'two-col' },
      h('div', { class: 'stack' }, options, tuning),
      h('div', { class: 'stack' },
        h('div', { id: 'log-fields' }, outcome ? fieldCard(outcome) : emptyBox({
          title: 'No analysis yet',
          body: 'Paste two or more events and press Propose a rule. You will see ' +
            'every field, whether it was pinned, and why.',
        })),
        h('div', { id: 'log-messages' }, outcome ? doubtsCard(outcome) : null),
        outcome ? h('div', { class: 'next-step' },
          h('span', { class: 'muted', text: 'The proposal is loaded as ' +
            'synthesized, which is recorded in its history.' }),
          btn('Load into Conditions \u2192', { kind: 'primary', onClick: adopt })) : null))});
}

function fieldCard(result) {
  const fields = result.fields || [];
  const pinned = fields.filter((f) => f.include).length;
  return card({
    title: 'Field stability',
    sub: fields.length + ' fields across ' + result.samples + ' samples \u00b7 ' +
      pinned + ' pinned, ' + (fields.length - pinned) + ' skipped',
    body: dataTable({
      columns: [
        { label: '' },
        { label: 'field' },
        { label: 'values', align: 'right' },
        { label: 'present', align: 'right' },
        { label: 'example' },
        { label: 'why skipped' },
      ],
      rows: fields.map((field) => [
        field.include
          ? badge('pin', 'ok')
          : badge('skip', null),
        h('span', { class: 'mono', text: field.name }),
        String(field.distinct),
        field.present + '/' + field.total,
        h('span', { class: 'mono', text: JSON.stringify(field.sample).slice(0, 34) }),
        h('span', { class: 'muted', text: (field.reasons || []).join('; ') || '\u2014' }),
      ]),
    }),
  });
}

function doubtsCard(result) {
  const diagnostics = result.diagnostics || [];
  if (!diagnostics.length) {
    return card({
      title: 'No warnings from the generator',
      body: h('p', { class: 'dim', text: 'The proposal came back with nothing to ' +
        'warn about. That is the generator saying it found no problem, not a ' +
        'promise that the rule is right: it was inferred from samples, not from ' +
        'a decision you made.' }),
    });
  }
  return card({
    title: 'What to check before trusting this',
    body: h('div', { class: 'stack' },
      ...diagnostics.map((note) => h('div', {
        class: 'problem', style: { gridTemplateColumns: '110px minmax(0,1fr)' },
      },
        h('span', { class: 'problem-code', text: note.code }),
        h('div', { class: 'problem-plain', text: note.message })))),
  });
}

function propose() {
  if (!form.text.trim()) { toast('Paste at least two events first.', 'bad'); return; }
  attempt(async () => {
    const data = await api.synthesize(form.text, form.format, {
      table: form.table.trim(),
      skip_volatile: form.skipVolatile,
      skip_timestamps: form.skipTimestamps,
      threshold: form.threshold,
      group_by: linesOf(form.groupBy.replace(/,/g, '\n')),
    });
    outcome = data;
    const doubts = (data.diagnostics || []).filter((d) => d.severity === 'problem').length;
    toast('Proposed a rule from ' + data.samples + ' samples' +
      (doubts ? ' with ' + doubts + ' thing(s) to check' : '') +
      '. It is a hypothesis \u2014 read the notes before deploying it.',
      doubts ? 'bad' : 'good');
    rerender();
  }, { context: 'draft' });
}

function adopt() {
  loadRule({
    payload: outcome.rule,
    provenance: state.ui.target,
    origin: 'synthesized',
    sourceText: form.text,
    entryId: null,
    parentId: null,
  });
  toast('Loaded as a synthesized rule. Saving records that it was proposed, ' +
    'not decided on.', 'good');
  go('conditions');
}
