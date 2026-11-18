/* 9 Versions — time travel.

   History is append-only. Tuning writes a new version pointing at the one it
   came from, so "put it back how it was" is always answerable — and the diff
   is what makes the answer readable. */

import { h, fmtTime, shortHash } from '../ui/dom.js';
import {
  badge, btn, card, codeBlock, emptyBox, input, select, toast,
} from '../ui/components.js';
import { state, loadRule, rerender, setTarget } from '../core/state.js';
import { attempt } from '../core/problems.js';
import { go } from '../core/router.js';
import { page } from './shared.js';
import * as api from '../core/api.js';

let opened = null;
let parentRule = null;
let lineage = [];

export function render(route, fresh) {
  if (fresh) {
    load();
    if (route.id) open(route.id);
  }

  const filters = card({
    title: 'Filter',
    body: h('div', { class: 'stack' },
      h('div', { class: 'row-3' },
        input({
          id: 'history-q',
          placeholder: 'search title, id, note',
          onKeydown: (event) => { if (event.key === 'Enter') load(); },
        }),
        select({
          id: 'history-origin',
          value: '',
          options: [
            { value: '', label: 'any origin' },
            { value: 'authored', label: 'authored' },
            { value: 'imported', label: 'imported' },
            { value: 'synthesized', label: 'synthesized' },
          ],
          onChange: () => load(),
        }),
        select({
          id: 'history-dialect',
          value: '',
          options: [{ value: '', label: 'any dialect' }].concat(
            state.cache.dialects.map((d) => ({ value: d.key, label: d.label })),
          ),
          onChange: () => load(),
        })),
      h('div', { class: 'split' },
        h('span', { class: 'muted', text: state.cache.versions.length + ' version(s) shown' }),
        btn('Refresh', { size: 'sm', kind: 'quiet', id: 'history-refresh', onClick: load }))),
  });

  return page('History', {
    eyebrow: 'Verify \u00b7 history',
    sub: 'Every saved version, with what it was derived from. Loading one into ' +
      'the editor does not change it; saving again records the next link.',
    body: h('div', { class: 'datasets-grid' },
      h('div', { class: 'stack' }, filters, card({ body: listBody(), tight: true })),
      h('div', { class: 'stack' },
        opened ? detailCard() : emptyBox({
          title: 'Nothing selected',
          body: 'Pick a version to see its lineage, its diff against the version ' +
            'it came from, and the text it was originally pasted as.',
        })))});
}

function listBody() {
  const versions = state.cache.versions;
  if (!versions.length) {
    return emptyBox({
      title: 'Nothing saved yet',
      body: 'Save a version from the top bar. Until then there is no history ' +
        'to compare against.',
      action: btn('Open the editor', { size: 'sm', onClick: () => go('details') }),
    });
  }
  const list = h('div', { class: 'records', id: 'history-list' });
  for (const entry of versions) {
    list.appendChild(h('button', {
      class: 'record' + (opened && opened.id === entry.id ? ' is-selected' : ''),
      type: 'button',
      on: { click: () => open(entry.id) },
    },
      badge(entry.origin, entry.origin),
      h('span', { class: 'record-title', text: entry.title || entry.rule_id || '(untitled)' }),
      h('span', { class: 'record-meta', text: '#' + entry.id + ' \u00b7 ' + entry.dialect + ' \u00b7 ' +
        fmtTime(entry.created_at) })));
  }
  return list;
}

function detailCard() {
  const entry = opened;
  const parent = lineage.find((item) => item.id === entry.parent_id) || null;
  return card({
    title: entry.title || entry.rule_id || '(untitled)',
    sub: '#' + entry.id + ' \u00b7 ' + entry.dialect + ' \u00b7 ' +
      fmtTime(entry.created_at) + (entry.note ? ' \u00b7 ' + entry.note : ''),
    actions: h('div', { class: 'row' },
      btn('Load into editor', {
        size: 'sm', kind: 'primary',
        onClick: () => {
          if (state.ui.dirty && !window.confirm(
            'The editor has unsaved changes. Loading this version discards them. Continue?',
          )) return;
          loadRule({
            payload: entry.rule,
            provenance: entry.dialect,
            origin: entry.origin || 'authored',
            sourceText: entry.source_text || '',
            entryId: entry.id,
            parentId: entry.id,
          });
          setTarget(entry.dialect);
          toast('Version ' + entry.id + ' loaded. Saving will record the next ' +
            'version as derived from it.', 'good');
          go('details');
        },
      }),
      btn('Delete', {
        size: 'sm', kind: 'quiet',
        onClick: () => {
          if (!window.confirm('Forget version #' + entry.id + '? This cannot be undone.')) return;
          attempt(async () => {
            await api.forgetEntry(entry.id);
            opened = null;
            toast('Version #' + entry.id + ' was forgotten.', 'good');
            load();
          }, { context: 'versions' });
        },
      })),
    body: h('div', { class: 'stack' },
      h('div', { class: 'row wrap' },
        badge(entry.origin, entry.origin),
        badge('rule id ' + entry.rule_id),
        parent ? badge('derived from #' + parent.id, null, parent.title) : badge('no parent'),
        entry.has_source ? badge('original text kept', 'ok') : null),
      h('h3', { text: 'Lineage, oldest first' }),
      lineageBody(),
      h('h3', { text: parent ? 'Changes since #' + parent.id : 'This is the first version in the chain' }),
      parent ? diffBody() : h('p', { class: 'muted', text: 'Nothing to compare against.' }),
      entry.source_text
        ? h('div', { class: 'stack' },
          h('h3', { text: 'As originally pasted' }),
          codeBlock({ text: entry.source_text, label: 'source text' }))
        : null),
  });
}

function lineageBody() {
  const timeline = h('div', { class: 'timeline', id: 'history-lineage' });
  for (const node of lineage) {
    timeline.appendChild(h('div', {
      class: 'timeline-node' + (opened && node.id === opened.id ? ' is-current' : ''),
    },
      h('div', { class: 'row' },
        badge(node.origin, node.origin),
        h('span', { class: 'card-title', text: '#' + node.id + ' ' +
          (node.title || node.rule_id || '(untitled)') })),
      h('div', { class: 'recent-meta', text: fmtTime(node.created_at) }),
      node.note ? h('div', { class: 'muted', text: node.note }) : null));
  }
  if (!lineage.length) {
    timeline.appendChild(h('p', { class: 'muted', text: 'No lineage recorded.' }));
  }
  return timeline;
}

function diffBody() {
  if (!parentRule) return h('p', { class: 'muted', text: 'Loading the parent version\u2026' });
  const rows = [];
  diff(parentRule.rule, opened.rule.rule, '', rows);
  if (!rows.length) {
    return h('p', { class: 'muted', text:
      'The two versions are structurally identical. A save without a change is ' +
      'still recorded — the record is the point.' });
  }
  const list = h('div', { class: 'diff' });
  for (const row of rows.slice(0, 80)) {
    list.appendChild(h('div', { class: 'diff-row ' + row.kind },
      h('span', { class: 'mono', text: row.path + ' ' }),
      row.kind === 'changed'
        ? h('span', { text: row.from + ' \u2192 ' + row.to })
        : h('span', { text: row.kind === 'added' ? row.to : row.from })));
  }
  if (rows.length > 80) {
    list.appendChild(h('div', { class: 'diff-row', text: '\u2026 and ' + (rows.length - 80) + ' more' }));
  }
  return list;
}

/** Structural diff over the encoded IR. Values are truncated: a diff is for
    finding what changed, not for reading a whole rule. */
function diff(a, b, path, out) {
  const kindA = a === null || a === undefined ? 'undefined' : typeof a;
  const kindB = b === null || b === undefined ? 'undefined' : typeof b;
  if (kindA === 'object' && kindB === 'object' && a !== null && b !== null) {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const key of keys) {
      const label = path ? path + '.' + key : key;
      if (!(key in a)) out.push({ kind: 'added', path: label, to: short(b[key]) });
      else if (!(key in b)) out.push({ kind: 'removed', path: label, from: short(a[key]) });
      else diff(a[key], b[key], label, out);
    }
    return;
  }
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    out.push({ kind: 'changed', path: path || '(rule)', from: short(a), to: short(b) });
  }
}

function short(value) {
  const text = value === undefined ? '\u2014' : JSON.stringify(value);
  return text && text.length > 60 ? text.slice(0, 60) + '\u2026' : String(text);
}

function load() {
  const value = (id) => (document.getElementById(id) || {}).value || '';
  attempt(async () => {
    const data = await api.history({
      q: value('history-q'),
      origin: value('history-origin'),
      dialect: value('history-dialect'),
      limit: 100,
    });
    state.cache.versions = data.entries || [];
    rerender();
  }, { context: 'versions' });
}

function open(id) {
  attempt(async () => {
    const entry = await api.entry(id);
    opened = entry;
    const chain = await api.lineage(id);
    lineage = chain.lineage || [];
    parentRule = null;
    rerender();
    if (entry.parent_id) {
      const parent = await api.entry(entry.parent_id);
      parentRule = parent.rule;
      rerender();
    }
  }, { context: 'versions' });
}

/** Save the rule currently in the editor. The top bar, Ctrl+S and the end of
    the Author walk-through all call this, so there is exactly one save path. */
export function saveVersionNow() {
  attempt(async () => {
    const entry = await api.saveVersion(state.doc.payload, {
      origin: state.doc.origin,
      sourceText: state.doc.sourceText,
      parentId: state.doc.parentId,
      note: '',
    });
    state.doc.parentId = entry.id;
    state.doc.entryId = entry.id;
    state.doc.origin = 'authored';

    state.ui.dirty = false;
    if (entry.rule_hash) state.status.ruleHash = entry.rule_hash;
    toast('Saved version ' + entry.id + '. The next save records itself as ' +
      'derived from it.', 'good');
    load();
  }, { context: 'save' });
}

export { shortHash };
