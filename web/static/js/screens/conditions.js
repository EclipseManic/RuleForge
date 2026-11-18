/* 3 Conditions — the filters, and only the filters.

   The nine other stage kinds live on their own screen. A dropdown that hides
   them in one line is how "what is this tool capable of" became unanswerable. */

import { h } from '../ui/dom.js';
import { btn, card } from '../ui/components.js';
import { conditionEditor } from '../ui/condition.js';
import { state, doc, stages, touch, rerender, mutate } from '../core/state.js';
import { newComparison, newStage, T, fieldRef, literal, comparison } from '../core/ir.js';
import { toast } from '../ui/components.js';
import { stepFooter, page } from './shared.js';

export function render() {
  const pipeline = stages();
  const filters = pipeline.filter((stage) => stage['@'] === 'Filter');

  const list = h('div', { class: 'stack' });
  if (!filters.length) {
    list.appendChild(emptyState());
  } else {
    filters.forEach((stage) => list.appendChild(conditionCard(stage)));
  }

  const add = h('div', { class: 'split' },
    h('span', { class: 'muted', text: filters.length +
      (filters.length === 1 ? ' filter condition' : ' filter conditions') +
      ' \u00b7 a rule with no filter matches every event' }),
    btn('+ Add condition', { kind: 'primary', onClick: addCondition }));

  const output = outputCard();

  return page('Conditions', {
    eyebrow: 'Step 3 of 6 \u00b7 author',
    sub: 'Every event has to survive all of these, in order. Group conditions ' +
      'with AND/OR rather than flattening them — a real rule is rarely a list.',
    actions: [h('span', {
      class: 'badge',
      text: state.doc.provenance,
      title: 'the dialect this rule was read from',
    })],
    body: h('div', { class: 'stack-lg' },
      add,
      list,
      output,
      stepFooter('conditions'))});
}

function conditionCard(stage) {
  const pipeline = stages();
  const index = pipeline.indexOf(stage);
  const header = h('div', { class: 'split' },
    h('div', { class: 'row' },
      h('span', { class: 'stage-kind', text: 'Filter' }),
      h('span', { class: 'stage-id', text: stage.id.v })),
    h('div', { class: 'row' },
      btn('\u2191', {
        size: 'sm', kind: 'quiet', title: 'move this stage earlier',
        onClick: () => move(stage, -1),
      }),
      btn('\u2193', {
        size: 'sm', kind: 'quiet', title: 'move this stage later',
        onClick: () => move(stage, 1),
      }),
      btn('duplicate', {
        size: 'sm', kind: 'quiet',
        onClick: () => {
          const copy = structuredClone(stage);
          copy.id = T.str(nextId('filter'));
          mutate(() => { pipeline.splice(index + 1, 0, copy); });
          rerender();
        },
      }),
      btn('\u00d7', {
        size: 'sm', kind: 'quiet', title: 'remove this filter',
        onClick: () => {
          /* A rule with no filter matches every event, so the last one stays
             and the refusal says why. */
          if (pipeline.filter((s) => s['@'] === 'Filter').length <= 1) {
            toast('a rule with no filter matches every event. Add another ' +
              'condition before removing this one.', 'bad');
            return;
          }
          mutate(() => { pipeline.splice(index, 1); });
          rerender();
        },
      })));

  return card({
    title: '',
    body: h('div', { class: 'stack' },
      header,
      conditionEditor(stage.condition, (next) => {
        mutate(() => { stage.condition = next || newComparison(); });
        rerender();
      })),
  });
}

function emptyState() {
  const example = comparison('==', fieldRef('EventID'), literal(T.dec('4688')));
  return h('div', { class: 'stack' },
    h('div', { class: 'card-body' },
      h('p', { class: 'dim' },
        'A filter needs at least one comparison. This is what one looks like:'),
      h('div', { class: 'cond-row', 'aria-hidden': 'true', style: { opacity: '0.55' } },
        h('span', { class: 'mono', text: 'current' }),
        h('span', { class: 'mono', text: 'EventID' }),
        h('span', { class: 'mono', text: '==' }),
        h('span', { class: 'mono', text: '4688' }),
        h('span')),
      btn('Start from this', {
        kind: 'primary',
        onClick: () => {
          const pipeline = stages();
          /* A run of filters is a natural AND: insert before the output. */
          const emitAt = pipeline.findIndex((s) => s['@'] === 'Emit');
          const filter = newStage('Filter', pipeline.length);
          filter.condition = example;
          mutate(() => {
            pipeline.splice(emitAt < 0 ? pipeline.length : emitAt, 0, filter);
          });
          rerender();
        },
      })),
    h('p', { class: 'field-hint', text: 'It is placed immediately before the ' +
      'output stage, where filters always run.' }));
}

function outputCard() {
  const emit = stages().find((s) => s['@'] === 'Emit');
  return card({
    title: 'Output',
    sub: 'Every rule ends in exactly one output stage. A pipeline without one ' +
      'returns whatever the last stage happened to leave.',
    body: h('div', { class: 'stack' },
      h('div', { class: 'row' },
        h('span', { class: 'stage-kind', text: 'Emit' }),
        h('span', { class: 'stage-id', text: emit ? emit.id.v : 'out' }),
        h('span', { class: 'muted', text: emit && emit.keeps.v.length
          ? 'keeps ' + emit.keeps.v.length + ' column(s)'
          : 'returns every column' })),
      h('p', { class: 'field-hint', text: 'The columns and de-duplication of ' +
        'the output are edited on the Stage library screen.' })),
    actions: btn('Edit output', { size: 'sm', onClick: () => { window.location.hash = '#/studio/author/stages'; } }),
  });
}

function move(stage, delta) {
  const pipeline = stages();
  const index = pipeline.indexOf(stage);
  const target = index + delta;
  /* Read stays first and Emit stays last. */
  if (target < 1 || target >= pipeline.length - 1) return;
  mutate(() => {
    pipeline.splice(index, 1);
    pipeline.splice(target, 0, stage);
  });
  rerender();
}

function addCondition() {
  const pipeline = stages();
  const emitAt = pipeline.findIndex((s) => s['@'] === 'Emit');
  const filter = newStage('Filter', pipeline.length);
  mutate(() => {
    pipeline.splice(emitAt < 0 ? pipeline.length : emitAt, 0, filter);
  });
  rerender();
}

function nextId(kind) {
  const taken = new Set(stages().map((s) => s.id.v));
  let index = stages().length;
  while (taken.has(kind + '_' + index)) index += 1;
  return kind + '_' + index;
}
