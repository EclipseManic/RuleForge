/* 10 Explain — what does someone else's rule really say?

   Lowering is the only honest way to answer that: the rule is parsed into the
   same structure the builder edits, so what you read is what the tool will
   render and test, not a summary written by a language model.

   "Nothing was lost" is a claim about the WHOLE path, so it is only printed
   when the rule parses AND every target language can write it. It used to be
   printed whenever the parser returned no diagnostics, which is how a rule
   that four of eight targets refuse came back as "Every clause in this rule is
   representable". */

import { h } from '../ui/dom.js';
import { badge, btn, card, emptyBox, field, select, textarea, toast } from '../ui/components.js';
import { state, loadRule, rerender, setTarget } from '../core/state.js';
import { attempt } from '../core/problems.js';
import { go } from '../core/router.js';
import { page } from './shared.js';
import * as api from '../core/api.js';

let text = '';
let dialect = 'sentinel';
let outcome = null;

export function render(route, fresh) {
  if (fresh && !state.cache.dialects.length) {
    attempt(async () => {
      const data = await api.dialects();
      state.cache.dialects = data.dialects || [];
      const ready = (data.dialects || []).find((d) => d.can_parse);
      if (ready && !dialect) dialect = ready.key;
      rerender();
    }, { context: 'explain' });
  }

  const input = card({
    title: 'The rule you found',
    body: h('div', { class: 'stack' },
      field({
        label: 'Language it is written in',
        control: select({
          id: 'import-dialect',
          value: dialect,
          options: state.cache.dialects.map((d) => ({
            value: d.key,
            label: d.label + ' (' + d.language + ')' + (d.status === 'ready' ? '' : ' \u2014 planned'),
            disabled: d.status !== 'ready',
            title: d.note || null,
          })),
          onChange: (event) => {
            dialect = event.target.value;
            /* The reading on screen was made in the PREVIOUS language. Leaving
               it there with a new label is how a Wazuh parse gets read as
               Sigma. */
            outcome = null;
            rerender();
          },
        }),
      }),
      field({
        label: 'Rule text',
        control: textarea({
          id: 'import-text',
          rows: 18,
          code: true,
          value: text,
          placeholder: 'SecurityEvent\n| where EventID == 4624\n| where LogonType == 3',
          onInput: (event) => { text = event.target.value; },
        }),
      }),
      btn('Read this rule', { kind: 'primary', block: true, id: 'import-go', onClick: analyze })),
    foot: h('span', {}, 'Anything that cannot be represented is reported rather ' +
      'than dropped. A rule that loses a clause in translation is a rule that ' +
      'matches something else.'),
  });

  const reading = card({
    title: 'What it says',
    sub: outcome ? 'Read as ' + outcome.dialect + ', in the order the stages run.' : 'Nothing read yet.',
    body: h('div', { id: 'import-outline' }, outcome ? outlineBody(outcome.outline) : emptyBox({
      title: 'Nothing to read yet',
      body: 'Paste a rule and press Read this rule. The outline is generated ' +
        'from the parsed structure, not from its text.',
    })),
  });

  return page('Explain a rule', {
    eyebrow: 'Derive \u00b7 paste and read',
    sub: 'Paste a rule someone else wrote. You get the structure, the plain ' +
      'meaning of every stage, and the list of anything that did not survive.',
    body: h('div', { class: 'two-col' },
      h('div', { class: 'stack' }, input),
      h('div', { class: 'stack' }, reading,
        h('div', { id: 'import-diagnostics' }, outcome ? diagnosticsCard(outcome) : null),
        outcome ? h('div', { class: 'next-step' },
          h('span', { class: 'muted', text: 'Tune it, or keep reading it as it is.' }),
          btn('Load into Conditions \u2192', { kind: 'primary', onClick: adopt })) : null))});
}

function outlineBody(outline) {
  if (!outline) return emptyBox({ body: 'The parser returned no outline.' });
  const box = h('div', { class: 'stack' });
  const an = outline.annotations || {};
  if (an.title) box.appendChild(h('h2', { text: an.title }));
  /* Wazuh's <description> fills BOTH fields, and printing it twice read as a
     bug in the rule rather than a quirk of the importer. */
  if (an.description && an.description !== an.title) {
    box.appendChild(h('p', { class: 'dim', text: an.description }));
  }
  const facts = [];
  if (an.severity) facts.push('severity ' + an.severity);
  if (an.author) facts.push('by ' + an.author);
  if (outline.language) facts.push(outline.language);
  if (facts.length) box.appendChild(h('div', { class: 'row wrap' },
    ...facts.map((fact) => badge(fact))));
  for (const entry of an.mitre_attack || []) {
    /* Wazuh carries technique ids and no tactic, so this used to print a line
       that began with a bare colon: ": T1059.001". */
    const techniques = (entry.techniques || []).join(', ');
    box.appendChild(h('div', { class: 'mono',
      text: entry.tactic
        ? entry.tactic + (techniques ? ': ' + techniques : '')
        : (techniques || 'ATT&CK') }));
  }

  for (const binding of outline.bindings || []) {
    box.appendChild(h('h3', { text: 'binding ' + binding.name }));
    if (binding.guard) {
      box.appendChild(h('div', { class: 'cond-readonly', text: 'guard: ' + binding.guard }));
    }
    for (const stage of binding.stages || []) box.appendChild(stageView(stage));
  }

  box.appendChild(h('h3', { text: 'pipeline' }));
  for (const stage of outline.pipeline || []) box.appendChild(stageView(stage));
  return box;
}

function stageView(stage) {
  const box = h('div', { class: 'timeline-node' },
    h('div', { class: 'row' },
      badge(stage.kind, 'info'),
      stage.id ? h('span', { class: 'stage-id', text: stage.id }) : null,
      stage.capability === 'declared_only'
        ? badge('appliance only', 'declared',
          'modelled and rendered correctly, but only the vendor engine can run it')
        : null),
    stage.condition ? h('div', { class: 'cond-readonly', text: stage.condition }) : null,
    stage.predicate ? h('div', { class: 'cond-readonly', text: stage.predicate }) : null);

  /* The settings a stage means by. A Correlation printed as a bare word left
     the reader unable to see how often, over what window, or on what key. */
  box.appendChild(detailLines(stage));

  /* A Sequence keeps its conditions on its steps, so the order is printed. */
  if (stage.ordered && stage.steps) {
    const facts = [];
    if (stage.by && stage.by.length) facts.push('joined on ' + stage.by.join(', '));
    if (stage.maxspan) facts.push('within ' + stage.maxspan);
    if (facts.length) box.appendChild(h('div', { class: 'field-hint', text: facts.join(' \u00b7 ') }));
    for (const step of stage.steps) {
      box.appendChild(h('div', { class: 'cond-readonly' },
        h('span', { class: 'stage-id', text: step.position + '. ' }),
        step.condition,
        step.runs > 1 ? h('span', { class: 'badge', text: step.runs + '\u00d7' }) : null));
    }
    if (stage.until) {
      box.appendChild(h('div', { class: 'cond-readonly', text: 'cancelled by: ' + stage.until }));
    }
  }
  if (stage.note) box.appendChild(h('div', { class: 'field-hint', text: stage.note }));
  return box;
}

/** The settings a stage means by, printed as sentences. */
function detailLines(stage) {
  const box = h('div', { class: 'stack' });
  const line = (text) => box.appendChild(h('div', { class: 'field-hint', text }));

  if (stage.table) {
    line('reads ' + stage.table +
      (stage.time_field ? ', timed by ' + stage.time_field : '') +
      (stage.selector ? ', narrowed by ' + stage.selector : ''));
  }

  if (stage.parent !== undefined && stage.parent !== null) {
    const parts = [];
    if (stage.frequency) parts.push('at least ' + stage.frequency + ' times');
    if (stage.timeframe) parts.push('within ' + stage.timeframe);
    if ((stage.group_by || []).length) parts.push('grouped by ' + stage.group_by.join(', '));
    line('fires when ' + (stage.parent || 'the parent rule') + ' matches ' +
      (parts.join(' ') || 'once'));
  }

  if ((stage.measures || []).length) {
    line(stage.measures.map((m) => m.function + '(' + (m.field || '*') + ')' +
      (m.distinct ? ' distinct' : '') + ' as ' + m.name).join(', ') +
      ((stage.keys || []).length ? ' per ' + stage.keys.join(', ') : ''));
  }

  if (Array.isArray(stage.keeps)) {
    line(stage.keeps.length ? 'keeps ' + stage.keeps.join(', ') : 'keeps every column');
  }
  if ((stage.dedupe_by || []).length) {
    line('de-duplicated on ' + stage.dedupe_by.join(', '));
  }
  if (Array.isArray(stage.keys) && stage.keys.length && !(stage.measures || []).length) {
    line('keyed by ' + stage.keys.map(
      (key) => (typeof key === 'string' ? key : key.field + (key.descending ? ' desc' : '')),
    ).join(', '));
  }
  return box;
}

/** What happened to this rule on the way in AND on the way out.
 *
 *  The card used to be printed from the PARSER's diagnostics alone, which is a
 *  claim about one third of the path. A rule can parse perfectly and still
 *  have no spelling in half the targets -- which is what the Wazuh correlation
 *  rule did while this card said nothing had been lost. */
function diagnosticsCard(result) {
  const lost = result.diagnostics || [];
  const renders = result.renders || [];
  const refused = renders.filter((entry) => !entry.ok);
  const body = h('div', { class: 'stack' });

  for (const note of lost) {
    body.appendChild(h('div', {
      class: 'problem', style: { gridTemplateColumns: '110px minmax(0,1fr)' },
    },
      h('span', { class: 'problem-code', text: note.code }),
      h('div', {},
        h('div', { class: 'problem-plain', text: note.message }),
        note.where ? h('div', { class: 'problem-engine', text: note.where }) : null)));
  }

  if (!renders.length) {
    body.appendChild(h('p', { class: 'dim', text: 'The target list had not arrived, ' +
      'so whether this rule can be written out has not been checked yet.' }));
  } else if (refused.length) {
    body.appendChild(h('p', { class: 'dim', text: 'It can be read, but ' +
      refused.length + ' of ' + renders.length + ' target languages cannot write it. ' +
      'That is a limit of the target, not a fault in the rule.' }));
    for (const entry of refused) {
      body.appendChild(h('div', {
        class: 'problem', style: { gridTemplateColumns: '110px minmax(0,1fr)' },
      },
        h('span', { class: 'problem-code', text: entry.code || 'RENDER' }),
        h('div', {},
          h('div', { class: 'problem-plain', text: entry.label + ': ' + entry.message }),
          h('div', { class: 'problem-engine', text: 'render ' + entry.key }))));
    }
  } else {
    body.appendChild(h('p', { class: 'dim', text: 'Every target language in this build ' +
      'can write it: ' + renders.map((entry) => entry.label).join(', ') + '.' }));
  }

  const clean = !lost.length && !refused.length && renders.length > 0;
  return card({
    title: clean ? 'Nothing was lost' : (lost.length + refused.length) + ' thing(s) did not survive',
    sub: clean
      ? 'Parsed, and writable in every target this build has.'
      : 'These are kept in the outline above and listed here, never dropped silently.',
    body,
  });
}

function analyze() {
  if (!text.trim()) { toast('Paste a rule first.', 'bad'); return; }
  attempt(async () => {
    const data = await api.lower(dialect, text, 'imported');
    const renders = await renderEverywhere(data.rule);
    outcome = {
      payload: data.rule,
      outline: data.outline,
      diagnostics: data.diagnostics || [],
      renders,
      dialect,
    };
    const lost = outcome.diagnostics.length;
    const refused = renders.filter((entry) => !entry.ok).length;
    toast(lost || refused
      ? 'Read the rule. ' + lost + ' clause(s) could not be represented and ' +
        refused + ' target(s) cannot write it \u2014 all listed rather than dropped.'
      : 'Read the rule. Everything in it was representable, and every target can write it.',
    lost || refused ? 'bad' : 'good');
    rerender();
  }, { context: 'explain' }).then((value) => {
    /* A read that FAILED must not leave the previous rule's outline and its
       "nothing was lost" card on screen beside the new error. */
    if (value === null) { outcome = null; rerender(); }
  });
}

/** Ask every ready target to write the rule.
 *
 *  This is the request that makes "nothing was lost" true or false. It costs
 *  one render per language and answers the question the pane claims to answer. */
async function renderEverywhere(payload) {
  const ready = (state.cache.dialects || []).filter((entry) => entry.status === 'ready');
  return Promise.all(ready.map(async (entry) => {
    try {
      await api.render(entry.key, payload);
      return { key: entry.key, label: entry.label, ok: true };
    } catch (err) {
      return {
        key: entry.key, label: entry.label, ok: false,
        code: err.code, message: err.message,
      };
    }
  }));
}

function adopt() {
  loadRule({
    payload: outcome.payload,
    provenance: dialect,
    origin: 'imported',
    sourceText: text,
    entryId: null,
    parentId: null,
  });
  setTarget(dialect);
  toast('Loaded into the editor as an imported rule. Save it to record where ' +
    'it came from.', 'good');
  go('conditions');
}
