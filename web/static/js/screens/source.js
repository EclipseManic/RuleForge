/* 2 Source — say where the events come from. */

import { h } from '../ui/dom.js';
import { card, field } from '../ui/components.js';
import { mutate } from '../core/state.js';
import { T } from '../core/ir.js';
import { boundText, stepFooter, page, readStage } from './shared.js';

export function render() {
  const read = readStage();

  const origin = card({
    title: 'Where events come from',
    body: h('div', {},
      field({
        label: 'Table or index',
        control: boundText({
          id: 'read-table',
          value: read ? read.table.v : '',
          placeholder: 'SecurityEvent',
          code: true,
          commit: (value) => {
            if (!read) return;
            const clean = value.trim();
            read.table = T.str(clean || 'events');
            /* The box would otherwise stay blank while the rule says `events`:
               the commit forces a default and nothing re-rendered the input. */
            if (!clean) {
              const box = document.getElementById('read-table');
              if (box) box.value = 'events';
            }
          },
        }),
        hint: 'The index, table or data stream your SIEM reads. ' +
          'Sentinel calls it a table, Splunk calls it an index.',
      }),
      field({
        label: 'Index-time selector',
        control: boundText({
          id: 'read-selector',
          value: read ? read.selector.v : '',
          placeholder: 'index=main sourcetype=WinEventLog',
          code: true,
          commit: (value) => { if (read) read.selector = T.str(value); },
        }),
        hint: 'Narrowing your SIEM applies before any event is read, in that ' +
          'SIEM\u2019s own words. Leave blank unless an imported rule had one.',
      }),
      field({
        label: 'Time field',
        control: boundText({
          id: 'read-timefield',
          value: read ? read.time_field.v : '',
          placeholder: 'TimeGenerated',
          code: true,
          commit: (value) => { if (read) read.time_field = T.str(value); },
        }),
        hint: 'Required only if the rule counts events over a window.',
      })),
  });

  const honesty = card({
    title: 'Two things this screen cannot do',
    body: h('div', { class: 'stack' },
      h('p', { class: 'dim' },
        'An index-time selector is applied by the SIEM before it reads an ' +
        'event. A local sample cannot reproduce that, so a test reports the ' +
        'selector as a caution instead of pretending it was applied.'),
      h('p', { class: 'dim' },
        'Several target languages cannot express a selector at all. When that ' +
        'happens the render says so, and the rendered rule matches more than ' +
        'this one — that warning is on the Preview screen, next to the text.')),
    foot: read && read.selector.v
      ? h('span', {}, 'This rule carries a selector: ',
        h('code', { class: 'mono', text: read.selector.v }))
      : h('span', { class: 'muted', text: 'No selector set.' }),
  });

  return page('Source', {
    eyebrow: 'Step 2 of 6 \u00b7 author',
    sub: 'Where the events come from, before any condition is applied.',
    body: h('div', { class: 'stack-lg' },
      h('div', { class: 'two-col' }, origin, honesty),
      stepFooter('source'))});
}
