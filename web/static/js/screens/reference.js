/* 12 Reference — the vocabulary, once, in one place.

   Every term the rest of the interface uses is defined here and linked from
   where it is used. The old UI explained each term next to each control, which
   is why it had fifteen hint paragraphs and still could not be read. */

import { h } from '../ui/dom.js';
import { badge, card, dataTable } from '../ui/components.js';
import { state, rerender } from '../core/state.js';
import { attempt, knownCodes, plainFor } from '../core/problems.js';
import { page } from './shared.js';
import * as api from '../core/api.js';

export function render(route, fresh) {
  if (fresh && !state.cache.dialects.length) {
    attempt(async () => {
      const data = await api.dialects();
      state.cache.dialects = data.dialects || [];
      rerender();
    }, { context: 'reference' });
  }

  if (fresh && !state.cache.vocabulary.codes.length) {
    attempt(async () => {
      const data = await api.vocabulary();
      state.cache.vocabulary = {
        operators: data.operators || [],
        codes: data.codes || [],
      };
      rerender();
    }, { context: 'reference' });
  }

  const highlight = route.code || null;
  if (highlight) {
    requestAnimationFrame(() => {
      const node = document.getElementById('code-' + highlight);
      if (node) node.scrollIntoView({ block: 'center', behavior: 'smooth' });
    });
  }

  const verdicts = card({
    title: 'The three verdicts',
    sub: 'A test answers one of these. There is no fourth answer, and no "probably".',
    body: h('div', { class: 'stack' },
      verdictRow('matched', 'The rule was answered: at least one event survived ' +
        'every stage.'),
      verdictRow('no_match', 'The rule was answered: every event was dropped. ' +
        'This is a real no, not an absence of evidence.'),
      verdictRow('not_evaluated', 'The rule could not be answered from the events ' +
        'given \u2014 usually a field the sample does not contain. One undecided row ' +
        'makes the whole verdict "could not tell", because a confident no built ' +
        'on a missing field is a false answer.')),
  });

  const origins = card({
    title: 'Where a rule came from',
    body: h('div', { class: 'stack' },
      h('div', { class: 'row' }, badge('authored', 'authored'),
        h('span', { class: 'dim', text: 'Written or edited here. A human decided what it matches.' })),
      h('div', { class: 'row' }, badge('imported', 'imported'),
        h('span', { class: 'dim', text: 'Pasted from an existing rule and read back into the builder.' })),
      h('div', { class: 'row' }, badge('synthesized', 'synthesized'),
        h('span', { class: 'dim', text: 'Proposed from log samples. A hypothesis until someone saves it as authored.' })),
      h('div', { class: 'row' }, badge('appliance only', 'declared'),
        h('span', { class: 'dim', text: 'declared_only: the step is modelled and rendered, ' +
          'but only the vendor engine can run it. A local test cannot evaluate it, and says so.' }))),
  });

  const matrix = card({
    title: 'What each language can do',
    sub: 'A language that cannot express a rule refuses; it never guesses.',
    body: state.cache.dialects.length
      ? dataTable({
        class: 'matrix',
        columns: [
          { label: 'language' }, { label: 'dialect' }, { label: 'reads a rule' },
          { label: 'writes a rule' }, { label: 'carries title' },
        ],
        rows: state.cache.dialects.map((d) => [
          d.label, h('span', { class: 'mono', text: d.key }),
          d.can_parse ? 'yes' : 'no',
          d.can_render ? 'yes' : 'no',
          d.carries_annotations ? 'yes' : 'no',
        ]),
      })
      : h('p', { class: 'muted', text: 'Loading the catalogue\u2026' }),
  });

  const differences = card({
    title: 'What each language will not do',
    sub: 'One card per dialect: the traps in that language, in the order they ' +
      'bite. Every one of these is a place where two dialects disagree about ' +
      'what the same words mean \u2014 which is why a render is refused by name ' +
      'instead of approximated.',
    body: state.cache.dialects.some((d) => d.note)
      ? h('div', { class: 'dialect-notes' },
        ...state.cache.dialects.filter((d) => d.note).map(dialectNote))
      : h('p', { class: 'muted', text: 'Loading the catalogue\u2026' }),
  });

  const codes = card({
    title: 'Every code this tool can show you',
    sub: allCodes().length + ' codes the engine can raise, each with the ' +
      'sentence it means. A screenshot is enough to search for one.',
    body: dataTable({
      class: 'code-table',
      columns: [{ label: 'code' }, { label: 'what it means' }],
      rows: allCodes().map((code) => [
        h('span', {
          id: 'code-' + code,
          class: code === highlight ? 'badge ok' : 'mono',
          text: code,
        }),
        h('span', { class: code === highlight ? 'problem-plain' : 'dim',
          text: plainFor(code, 'No plain sentence for this one yet \u2014 the ' +
            'engine\u2019s own message is shown verbatim when it fires.') }),
      ]),
    }),
    foot: h('span', {}, 'Some codes exist only inside the engine and are surfaced ' +
      'with their own message. An unknown code is shown verbatim rather than ' +
      'reinterpreted.'),
  });

  return page('Reference', {
    eyebrow: 'Reference',
    sub: 'The vocabulary once, so no other screen has to explain itself twice.',
    body: h('div', { class: 'stack-lg' },
      h('div', { class: 'two-col' }, verdicts, origins),
      matrix,
      differences,
      codes)});
}

/* -- the per-dialect notes ------------------------------------------------ */

/** The engine's notes are one paragraph per dialect. Printed as a paragraph
    they are unreadable, so each sentence becomes a point: the first sentence
    is the thing to know, the rest are the places it bites. */
function dialectNote(dialect) {
  return h('article', { class: 'dialect-note' },
    h('header', { class: 'dialect-note-head' },
      h('span', { class: 'dialect-note-name', text: dialect.label }),
      h('span', { class: 'mono muted', text: dialect.key }),
      h('span', { class: 'dialect-note-tags' },
        h('span', { class: 'badge', text: dialect.language }),
        h('span', { class: 'badge', text: dialect.can_parse ? 'reads' : 'writes only' }))),
    h('ul', { class: 'dialect-points' },
      ...pointsOf(dialect.note).map((point) => h('li', {}, ...richText(point)))));
}

/** Split a note into sentences without a tokenizer: a full stop followed by a
    space and a capital, a backtick or an opening parenthesis is the boundary
    the notes actually use. */
function pointsOf(note) {
  return String(note || '')
    .split(/(?<=[.;])\s+(?=[A-Z`(])/)
    .map((point) => point.trim())
    .filter(Boolean);
}

/** Backticks become <code>, because the notes use them for field names and
    operators and a wall of undifferentiated prose is what we are fixing. */
function richText(text) {
  return text.split('`').map((part, index) => (index % 2
    ? h('code', { text: part })
    : part));
}

/* Every code, from the engine itself.

   The table here used to be a hand-written list of 26 while the engine could
   raise more than 400, so the page that exists to explain a code could not
   explain most of them. The list is now the engine's own; the plain sentences
   are still local, and a code without one says so instead of being hidden. */
function allCodes() {
  const engine = (state.cache.vocabulary && state.cache.vocabulary.codes) || [];
  const merged = new Set([...engine, ...knownCodes()]);
  return [...merged].sort();
}

function verdictRow(kind, description) {
  return h('div', { class: 'verdict ' + kind },
    h('span', { class: 'verdict-word', text: {
      matched: 'Matched', no_match: 'No match', not_evaluated: 'Could not tell',
    }[kind] }),
    h('span', { class: 'verdict-note', text: description }));
}
