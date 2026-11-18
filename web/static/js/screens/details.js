/* 1 Details — name the rule.

   The paperwork, and only the paperwork. Source, conditions and output each
   have their own screen, because mixing them is what made the old form read
   like a settings page for the whole tool. */

import { h } from '../ui/dom.js';
import { card, field, select } from '../ui/components.js';
import { state, doc, mutate, touch } from '../core/state.js';
import { T } from '../core/ir.js';
import {
  annotations, boundText, boundTextarea, listFromText, listText, mitreFromText,
  mitreToText, stepFooter, noteRuleId, page, severityOptions, templateStrip,
} from './shared.js';

/** Where this rule came from, in a sentence that is true for its origin.

    "marked synthesized, from sentinel" read as though the rule had been parsed
    out of Sentinel text. A synthesized rule is proposed from log samples and is
    merely WRITTEN for that dialect. */
function provenanceLine() {
  const origin = state.doc.origin;
  const dialect = state.doc.provenance;
  if (origin === 'synthesized') {
    return 'Provenance: proposed from log samples, written for ' + dialect + '.';
  }
  if (origin === 'imported') {
    return 'Provenance: read from ' + dialect + ' text, then edited here.';
  }
  return 'Provenance: authored here, written for ' + dialect + '.';
}

export function render() {
  const an = annotations();

  const identity = card({
    title: 'Identity',
    sub: 'What an analyst sees at 3 a.m.',
    body: h('div', {},
      field({
        label: 'Title',
        control: boundText({
          id: 'an-title',
          value: an.title.v,
          placeholder: 'LSASS access from an unsigned process',
          commit: (value) => { an.title = T.str(value); },
        }),
        hint: 'The alert name an analyst reads first. Say what happened, not what the query does.',
      }),
      field({
        label: 'Rule id',
        control: boundText({
          id: 'rule-id',
          value: doc().rule_id.v,
          placeholder: 'lsass-ntlm-001',
          code: true,
          commit: (value) => {
            const id = value.trim() || 'rule';
            doc().rule_id = T.str(id);
            noteRuleId(id);
          },
        }),
        hint: 'A stable handle for this rule. Never shown in an alert.',
      }),
      field({
        label: 'Description',
        control: boundTextarea({
          id: 'an-description',
          value: an.description.v,
          rows: 3,
          placeholder: 'What the rule detects, and what an analyst should do when it fires.',
          commit: (value) => { an.description = T.str(value); },
        }),
      })),
  });

  const triage = card({
    title: 'Triage',
    sub: 'How this is routed and attributed.',
    body: h('div', {},
      h('div', { class: 'row-2' },
        field({
          label: 'Severity',
          control: select({
            id: 'an-severity',
            value: an.severity.v,
            options: severityOptions,
            onChange: (event) => {
              mutate(() => { an.severity = T.str(event.target.value); });
            },
          }),
        }),
        field({
          label: 'Author',
          control: boundText({
            id: 'an-author',
            value: an.author.v,
            commit: (value) => { an.author = T.str(value); },
          }),
        })),
      field({
        label: 'MITRE ATT&CK',
        control: boundTextarea({
          id: 'an-mitre',
          value: mitreToText(),
          rows: 2,
          code: true,
          placeholder: 'credential-access: T1003, T1003.001',
          commit: (value) => { an.mitre_attack = T.tuple(mitreFromText(value)); },
        }),
        hint: 'One tactic per line; techniques after a colon, comma-separated.',
      })),
  });

  const evidence = card({
    title: 'References and false positives',
    sub: 'One per line.',
    body: h('div', {},
      field({
        label: 'References',
        control: boundTextarea({
          id: 'an-references',
          value: listText(an.references),
          rows: 3,
          code: true,
          placeholder: 'https://attack.mitre.org/techniques/T1003/001/',
          commit: (value) => { an.references = listFromText(value); },
        }),
      }),
      field({
        label: 'Known false positives',
        control: boundTextarea({
          id: 'an-fps',
          value: listText(an.false_positives),
          rows: 3,
          placeholder: 'EDR agents that read lsass memory',
          commit: (value) => { an.false_positives = listFromText(value); },
        }),
        hint: 'Writing these down now is what stops the rule being muted later.',
      })),
  });

  return page('Details', {
    eyebrow: 'Step 1 of 6 \u00b7 author',
    sub: 'Name the rule and say how it should be triaged. Nothing here changes ' +
      'what it matches.',
    body: h('div', { class: 'stack-lg' },
      h('div', { class: 'two-col' }, identity, h('div', { class: 'stack' }, triage, evidence)),
      h('p', { class: 'muted', text: provenanceLine() }),

      templateStrip(),
      stepFooter('details'))});
}
