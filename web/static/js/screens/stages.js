/* 4 Stage library — every non-Filter step, with room to explain itself.

   A dropdown that hides ten concepts in one line is how an analyst concludes
   the tool can only filter. Each card states what the stage does, what it
   needs, and a worked example; inserting one puts it in the pipeline before
   the output, where it actually runs. */

import { h } from '../ui/dom.js';
import { badge, btn, card, toast } from '../ui/components.js';
import { renderStageBody } from '../ui/stage.js';
import { state, stages, mutate, rerender } from '../core/state.js';
import { STAGE_LIBRARY, T, newStage } from '../core/ir.js';
import { stepFooter, page } from './shared.js';

export function render() {
  const pipeline = stages();

  const library = h('div', { class: 'lib-grid' },
    ...STAGE_LIBRARY.filter((entry) => entry.kind !== 'Filter').map(
      (entry) => libraryCard(entry, pipeline),
    ));

  const ordered = h('div', { class: 'stack', id: 'stages' },
    ...pipeline.map((stage, index) => stageCard(stage, index, pipeline)));

  return page('Stage library', {
    eyebrow: 'Step 4 of 6 \u00b7 author',
    sub: 'Filters are on their own screen. Everything else a rule can do is here, ' +
      'with the form it needs. A stage inserted here runs before the output, always.',
    body: h('div', { class: 'stack-lg' },
      h('div', { class: 'stack' }, library),
      h('div', { class: 'stack' },
        h('div', { class: 'split' },
          h('h2', { text: 'Stages in this rule, in order' }),
          h('span', { class: 'muted', text: pipeline.length + ' stages \u00b7 events ' +
            'fall through them top to bottom' })),
        ordered),
      stepFooter('stages'))});
}

function libraryCard(entry, pipeline) {
  const existing = pipeline.filter((stage) => stage['@'] === entry.kind);
  return h('div', { class: 'lib-card' },
    h('div', { class: 'split' },
      h('span', { class: 'lib-name', text: entry.kind }),
      existing.length ? badge(existing.length + ' in rule', 'ok') : null),
    h('p', { class: 'lib-what', text: entry.what }),
    h('div', { class: 'lib-example', text: entry.example }),
    h('div', { class: 'field-hint', text: 'Needs: ' + entry.needs }),
    h('div', { class: 'btn-row' },
      btn('Insert into rule', {
        size: 'sm', kind: 'primary',
        onClick: () => insert(entry.kind),
      }),
      existing.length ? btn('Edit in place \u2192', {
        size: 'sm', kind: 'quiet',
        onClick: () => {
          const node = document.getElementById('stage-' + existing[0].id.v);
          if (node) {
            node.scrollIntoView({ block: 'center', behavior: 'smooth' });
            node.classList.add('is-selected');
          }
        },
      }) : null));
}

function stageCard(stage, index, pipeline) {
  const kind = stage['@'];
  const cardId = 'stage-' + stage.id.v;
  const readonlyReason = kind === 'Read'
    ? 'The source is edited on the Source screen.'
    : kind === 'Filter'
      ? 'Filters are edited on the Conditions screen.'
      : null;

  const head = h('div', { class: 'stage-head' },
    h('span', { class: 'stage-kind', text: kind }),
    h('span', { class: 'stage-id', text: stage.id.v }),
    stage.capability && stage.capability.v === 'declared_only'
      ? badge('appliance only', 'declared')
      : null,
    h('span', { class: 'grow' }),
    kind !== 'Emit'
      ? h('div', { class: 'row' },
        btn('\u2191', {
          size: 'sm', kind: 'quiet', title: 'move earlier',
          onClick: () => move(index, -1),
        }),
        btn('\u2193', {
          size: 'sm', kind: 'quiet', title: 'move later',
          onClick: () => move(index, 1),
        }),
        btn('\u00d7', {
          size: 'sm', kind: 'quiet', title: 'remove this stage',
          onClick: () => remove(index),
        }))
      : null);

  const body = h('div', { class: 'stage-body' });
  const node = h('div', { class: 'stage-card' + (kind === 'Emit' ? ' stage-terminal' : ''), id: cardId },
    head);
  if (readonlyReason) {
    body.appendChild(h('p', { class: 'field-hint', text: readonlyReason }));
    body.appendChild(h('div', { class: 'row' },
      btn(kind === 'Read' ? 'Open Source' : 'Open Conditions', {
        size: 'sm', kind: 'quiet',
        onClick: () => {
          window.location.hash = '#/studio/author/' + (kind === 'Read' ? 'source' : 'conditions');
        },
      })));
  } else {
    renderStageBody(body, stage);
  }
  node.appendChild(body);
  return node;
}

function insert(kind) {
  const pipeline = stages();
  const emitAt = pipeline.findIndex((s) => s['@'] === 'Emit');
  const stage = newStage(kind, pipeline.length);
  /* A Correlation points at the stage it counts. `newStage` fills in the id
     `source`, which only exists in a brand-new rule: an imported pipeline uses
     ids like `r100900_source`, so the new stage referred to a stage that was
     not there and the rule refused on render. */
  if (kind === 'Correlation') {
    const read = pipeline.find((s) => s['@'] === 'Read');
    if (read) stage.parent = T.str(read.id.v);
  }
  /* A unique id: two stages with the same id make the trace unreadable and the
     output ambiguous. */
  const taken = new Set(pipeline.map((s) => s.id.v));
  let n = pipeline.length;
  while (taken.has(stage.id.v)) {
    n += 1;
    stage.id = T.str(kind.toLowerCase() + '_' + n);
  }
  mutate(() => {
    pipeline.splice(emitAt < 0 ? pipeline.length : emitAt, 0, stage);
  });
  toast('A ' + kind + ' stage was inserted before the output. Fill in its form ' +
    'below, then check Preview.', 'good');
  rerender();
  requestAnimationFrame(() => {
    const node = document.getElementById('stage-' + stage.id.v);
    if (node) {
      node.scrollIntoView({ block: 'center', behavior: 'smooth' });
      node.classList.add('is-selected');
    }
  });
}

function move(index, delta) {
  const pipeline = stages();
  const target = index + delta;
  /* Read stays first, Emit stays last. */
  if (target < 1 || target >= pipeline.length - 1) return;
  mutate(() => {
    const [stage] = pipeline.splice(index, 1);
    pipeline.splice(target, 0, stage);
  });
  rerender();
}

function remove(index) {
  const pipeline = stages();
  const stage = pipeline[index];
  if (stage['@'] === 'Emit' || stage['@'] === 'Read') {
    toast('The source and the output are not stages you can remove.', 'bad');
    return;
  }
  mutate(() => { pipeline.splice(index, 1); });
  rerender();
  void state;
}
