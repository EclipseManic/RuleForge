/* Small helpers shared by the screens: the page head, the step footer, bound
   inputs, and the two ways to start a rule. */

import { h } from '../ui/dom.js';
import { btn, toast } from '../ui/components.js';
import {
  state, doc, mutate, touch, stages, loadRule, rerender, setTarget,
} from '../core/state.js';
import { go, nextStepOf, previousStepOf } from '../core/router.js';
import { T, linesOf, TEMPLATES, emptyRule } from '../core/ir.js';
import { attempt } from '../core/problems.js';
import * as api from '../core/api.js';

export const annotations = () => doc().annotations;

export const readStage = () => stages().find((s) => s['@'] === 'Read') || null;

export function page(title, options) {
  const opts = options || {};
  return h('div', { class: 'page' },
    h('div', { class: 'page-head' },
      h('div', { class: 'grow' },
        h('span', { class: 'eyebrow', text: opts.eyebrow || '' }),
        h('h1', { text: title }),
        opts.sub ? h('p', { class: 'page-sub', text: opts.sub }) : null),
      opts.actions ? h('div', { class: 'btn-row' }, opts.actions) : null),
    opts.body || null);
}

/** The bottom of every authoring screen: back, forward, and where you are.

    Both directions are always here, even at the ends. On the first step the
    back button is present and disabled rather than absent, because a button
    that disappears is how a workflow starts feeling like a maze; on the last
    step the forward button becomes the save, which is the only thing left to
    do. */
export function stepFooter(current) {
  const previous = previousStepOf(current);
  const next = nextStepOf(current);
  return h('div', { class: 'step-foot' },
    btn('\u2190 Previous', {
      id: 'prev-step',
      disabled: !previous,
      ariaLabel: previous
        ? 'Back to ' + previous.label
        : 'This is the first step',
      onClick: previous ? () => go(previous.name) : undefined,
    }),
    h('span', {
      class: 'step-foot-hint',
      text: next
        ? 'Step ' + next.step + ' of 6 \u00b7 ' + next.label + ' comes next.'
        : 'Step 6 of 6 \u00b7 the end of the walk-through.',
    }),
    next
      ? btn('Next: ' + next.label + ' \u2192', {
        kind: 'primary',
        id: 'next-step',
        onClick: () => go(next.name),
      })
      : btn('Save version', {
        kind: 'primary',
        id: 'next-step',
        ariaLabel: 'Record this rule as a version',
        onClick: () => document.querySelector('#save-version').click(),
      }));
}

/* -- starting a rule ------------------------------------------------------ */

/** A blank rule that is still valid: a source, one comparison, an output. */
export function startBlank() {
  if (state.ui.dirty && !window.confirm(
    'The editor has unsaved changes. Starting from nothing discards them. Continue?',
  )) return;
  loadRule({
    payload: emptyRule(),
    provenance: state.ui.target,
    origin: 'authored',
    sourceText: '',
    entryId: null,
    parentId: null,
  });
  go('details');
  rerender();
}

/** Lowered by the server, so a template can never drift out of step with what
    the parser accepts. */
export async function loadTemplate(template) {
  await attempt(async () => {
    const data = await api.lower(template.dialect, template.text, template.id);
    loadRule({
      payload: data.rule,
      provenance: template.dialect,
      origin: 'authored',
      sourceText: template.text,
      entryId: null,
      parentId: null,
    });
    /* Through setTarget: the template decides the dialect the rule came FROM,
       so every mirror of the target has to follow it. */
    setTarget(template.dialect);
    if (data.diagnostics && data.diagnostics.length) {
      toast(data.diagnostics.length + ' thing(s) in this template could not be ' +
        'represented. They are listed on Preview.', 'bad');
    } else {
      toast('"' + template.title + '" is loaded. Press Next to walk through it.', 'good');
    }
    go('details');
    rerender();
  }, { context: 'templates' });
}

/** A one-line way back to a template from inside Author, so the only door is
    not the Home page. */
export function templateStrip() {
  return h('div', { class: 'template-strip' },
    h('span', { class: 'template-strip-label', text: 'Or start from a template' }),
    ...TEMPLATES.map((template) => h('button', {
      class: 'chip',
      type: 'button',
      title: 'Load "' + template.title + '" into the editor',
      on: { click: () => loadTemplate(template) },
    }, template.title)));
}

/* -- bound inputs --------------------------------------------------------- */

/** Bind a text input to a tagged IR field, without losing the caret. */
export function boundText(options) {
  const opts = options || {};
  return h('input', {
    class: 'input' + (opts.code ? ' code' : ''),
    id: opts.id || null,
    type: opts.type || 'text',
    value: opts.value || '',
    placeholder: opts.placeholder || null,
    spellcheck: false,
    autocomplete: 'off',
    on: {
      input: () => {
        const node = document.getElementById(opts.id);
        mutate(() => { opts.commit(node ? node.value : ''); });
        if (opts.afterInput) opts.afterInput();
      },
      change: opts.onChange,
    },
  });
}

export function boundTextarea(options) {
  const opts = options || {};
  return h('textarea', {
    class: 'textarea' + (opts.code ? ' code' : ''),
    id: opts.id || null,
    rows: opts.rows || 4,
    placeholder: opts.placeholder || null,
    spellcheck: false,
    value: opts.value || '',
    on: {
      input: () => {
        const node = document.getElementById(opts.id);
        mutate(() => { opts.commit(node ? node.value : ''); });
      },
    },
  });
}

/* -- annotation helpers --------------------------------------------------- */

export const mitreToText = () => annotations().mitre_attack.v.map((pair) => {
  const tactic = pair.v[0].v;
  const techniques = pair.v[1].v.map((t) => t.v).join(', ');
  return techniques ? tactic + ': ' + techniques : tactic;
}).join('\n');

export const mitreFromText = (text) => linesOf(text).map((line) => {
  const colon = line.indexOf(':');
  const tactic = colon < 0 ? line.trim() : line.slice(0, colon).trim();
  const techniques = colon < 0 ? []
    : line.slice(colon + 1).split(',').map((t) => t.trim()).filter(Boolean);
  return T.tuple([T.str(tactic), T.tuple(techniques.map(T.str))]);
});

export const listText = (tuple) => tuple.v.map((item) => item.v).join('\n');
export const listFromText = (text) => T.tuple(linesOf(text).map(T.str));

export const severityOptions = [
  { value: '', label: '\u2014' },
  { value: 'informational', label: 'informational' },
  { value: 'low', label: 'low' },
  { value: 'medium', label: 'medium' },
  { value: 'high', label: 'high' },
  { value: 'critical', label: 'critical' },
];

/** Set the id used in the URL once the rule is saved. */
export function noteRuleId(value) {
  state.doc.ruleId = value || 'draft';
}

export { touch };
