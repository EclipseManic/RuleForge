/* 7 Datasets — the library of sample logs.

   A dataset is evidence with a name and a hash. It is the only thing a test
   can be repeated against tomorrow and be known to be the same test. */

import { h, fmtTime, shortHash } from '../ui/dom.js';
import {
  badge, btn, card, emptyBox, field, input, select, textarea, toast,
} from '../ui/components.js';
import { state, rerender } from '../core/state.js';
import { attempt } from '../core/problems.js';
import { go } from '../core/router.js';
import { page } from './shared.js';
import * as api from '../core/api.js';

let selected = null;
let detail = null;
let draft = { name: '', format: 'jsonl', table: 'events', labels: '', description: '', text: '' };

export function render(route, fresh) {
  if (fresh) {
    if (route.id) open(route.id);
    else load();
  }

  const create = card({
    title: 'Save a new dataset',
    sub: 'Paste events once; they are stored locally with a hash.',
    body: h('div', {},
      field({
        label: 'Name',
        control: input({
          id: 'dataset-name',
          value: draft.name,
          placeholder: 'Windows logon baseline',
          onInput: (event) => { draft.name = event.target.value; },
        }),
      }),
      h('div', { class: 'row-2' },
        field({
          label: 'Format',
          control: select({
            id: 'dataset-format',
            value: draft.format,
            options: [
              { value: 'jsonl', label: 'JSONL' },
              { value: 'json', label: 'JSON array' },
              { value: 'kv', label: 'key=value' },
              { value: 'syslog', label: 'syslog' },
            ],
            onChange: (event) => { draft.format = event.target.value; },
          }),
        }),
        field({
          label: 'Table or index',
          control: input({
            id: 'dataset-table',
            value: draft.table,
            onInput: (event) => { draft.table = event.target.value; },
          }),
        })),
      field({
        label: 'Labels',
        control: input({
          id: 'dataset-labels',
          value: draft.labels,
          placeholder: 'benign, windows, baseline',
          onInput: (event) => { draft.labels = event.target.value; },
        }),
      }),
      field({
        label: 'Description',
        control: textarea({
          id: 'dataset-description',
          rows: 2,
          value: draft.description,
          placeholder: 'What this sample represents and where it came from.',
          onInput: (event) => { draft.description = event.target.value; },
        }),
      }),
      field({
        label: 'Raw events',
        control: textarea({
          id: 'dataset-text',
          rows: 9,
          code: true,
          value: draft.text,
          placeholder: '{"EventID": 4624, "Computer": "WS-01"}',
          onInput: (event) => { draft.text = event.target.value; },
        }),
      }),
      btn('Save dataset', { kind: 'primary', block: true, id: 'dataset-save', onClick: save })),
  });

  const library = card({
    title: 'Local datasets',
    sub: 'Stored locally, newest first.',
    actions: h('div', { class: 'row' },
      h('span', { class: 'badge', id: 'dataset-count', text: String(state.cache.datasets.length) }),
      btn('Refresh', { size: 'sm', kind: 'quiet', id: 'dataset-refresh', onClick: load }),
      btn('Search', { size: 'sm', id: 'dataset-search', onClick: load })),
    body: h('div', { class: 'stack' },
      input({
        id: 'dataset-q',
        placeholder: 'Search by name, label or table',
        onKeydown: (event) => { if (event.key === 'Enter') load(); },
      }),
      listBody()),
  });

  return page('Datasets', {
    eyebrow: 'Verify \u00b7 evidence library',
    sub: 'Named samples, kept on this machine. A test run records the dataset ' +
      'hash, so "the same test" is a fact rather than a memory.',
    body: h('div', { class: 'datasets-grid' },
      h('div', { class: 'stack' }, create),
      h('div', { class: 'stack' }, library,
        h('div', { id: 'dataset-preview' }, detail ? detailCard() : emptyBox({
          title: 'Nothing selected',
          body: 'Pick a dataset to see its normalized events and where it came from.',
        }))))});
}

function listBody() {
  const datasets = state.cache.datasets;
  if (!datasets.length) {
    return emptyBox({
      title: 'No datasets yet',
      body: 'Save a sample from the form on the left, then test against it from ' +
        'the Test screen or the Receipts screen.',
    });
  }
  const list = h('div', { class: 'records', id: 'dataset-list' });
  for (const item of datasets) {
    list.appendChild(h('button', {
      class: 'record' + (selected === item.id ? ' is-selected' : ''),
      type: 'button',
      on: { click: () => open(item.id) },
    },
      h('span', { class: 'record-title', text: item.name }),
      h('span', { class: 'record-meta', text: item.event_count + ' ev \u00b7 ' + item.format }),
      h('span', { class: 'record-meta', text: '#' + item.id })));
  }
  return list;
}

function detailCard() {
  const events = detail.events || [];
  return card({
    title: detail.name,
    sub: '#' + detail.id + ' \u00b7 ' + detail.format + ' \u00b7 table ' + detail.table +
      ' \u00b7 saved ' + fmtTime(detail.created_at),
    actions: h('div', { class: 'row' },
      btn('Use in a test \u2192', {
        size: 'sm', kind: 'primary',
        onClick: () => {
          state.status.datasetHash = detail.content_hash;
          window.location.hash = '#/studio/author/test?dataset=' + detail.id;
        },
      })),
    body: h('div', { class: 'stack' },
      h('div', { class: 'row wrap' },
        badge(events.length + ' events', 'info'),
        badge('hash ' + shortHash(detail.content_hash), null, detail.content_hash),
        ...(detail.labels || []).map((label) => badge(label)),
        detail.event_count !== events.length
          ? badge('display truncated', 'caution',
            'the server sent ' + events.length + ' of ' + detail.event_count + ' events')
          : null),
      detail.description ? h('p', { class: 'dim', text: detail.description }) : null,
      (detail.warnings || []).length
        ? h('div', { class: 'stack' },
          ...detail.warnings.map((warning) => h('div', { class: 'problem' },
            h('span', { class: 'problem-code', text: 'DATASET_WARNING' }),
            h('span', { class: 'problem-plain', text: warning }))))
        : null,
      h('div', { class: 'code' },
        h('div', { class: 'code-head' }, h('span', { text: 'normalized events' })),
        h('pre', { text: JSON.stringify(events, null, 2) }))),
  });
}

function load() {
  const query = document.getElementById('dataset-q');
  attempt(async () => {
    const data = await api.datasets(query ? query.value.trim() : '');
    state.cache.datasets = data.datasets || [];
    if (selected && !state.cache.datasets.some((d) => d.id === selected)) selected = null;
    rerender();
  }, { context: 'datasets' });
}

function open(id) {
  attempt(async () => {
    const data = await api.dataset(id);
    selected = data.id;
    detail = data;
    if (!state.cache.datasets.some((d) => d.id === data.id)) {
      const list = await api.datasets('');
      state.cache.datasets = list.datasets || [];
    }
    rerender();
  }, { context: 'datasets' });
}

function save() {
  if (!draft.name.trim()) { toast('Give the dataset a name first.', 'bad'); return; }
  if (!draft.text.trim()) { toast('Paste at least one event.', 'bad'); return; }
  attempt(async () => {
    const data = await api.saveDataset({
      name: draft.name.trim(),
      description: draft.description,
      format: draft.format,
      table: draft.table.trim() || 'events',
      labels: draft.labels.split(',').map((l) => l.trim()).filter(Boolean),
      text: draft.text,
    });
    draft = { name: '', format: 'jsonl', table: 'events', labels: '', description: '', text: '' };
    selected = data.id;
    toast('Dataset ' + data.id + ' saved with ' + data.event_count + ' event(s).', 'good');
    /* One fetch, not three: the list used to be fetched here and thrown away,
       then fetched again by open(), then a third time by the navigation. */
    go('datasets', { id: data.id });
  }, { context: 'datasets' });
}
