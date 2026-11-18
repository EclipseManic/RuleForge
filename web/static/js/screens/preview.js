/* 5 Preview — the rule in another language.

   The pane names the language next to the text, and a render that is older
   than the rule says so in words. The old UI let the label contradict the
   content, which is how KQL got copied into a Splunk deployment. */

import { h } from '../ui/dom.js';
import { badge, btn, card, codeBlock, toast } from '../ui/components.js';
import { state, rerender, setTarget } from '../core/state.js';
import { attempt } from '../core/problems.js';
import { stepFooter, page } from './shared.js';
import * as api from '../core/api.js';

/* `requested` is the target a request is out for; `target` is the target the
   text on screen was actually produced by. Keeping them apart stops a redraw
   during a request from firing the same request twice. */
/* `serial` is the identity of the rule the text was rendered from. Without it
   a render requested while the rule was still blank (a fresh session, before
   the example loads) stays on screen after the real rule arrives, wearing the
   rule's name — the exact stale pane this screen exists to prevent. */
let last = {
  text: '', target: null, requested: null, serial: -1, edits: -1,
  diagnostics: [], refusal: null,
};

export function render(route, fresh) {
  /* Re-render on arrival: the rule may have changed on another screen, and a
     stale pane that looks authoritative is the one failure this tool must
     never have. */
  /* Re-render when arriving, and whenever the target was changed somewhere
     else — the top bar, Home's tabs. A pane labelled with a language it is
     not written in is the exact failure this screen exists to prevent. */
  if (fresh || last.requested !== state.ui.target || last.serial !== state.ui.serial) {
    doRender();
  }

  const stale = last.edits !== state.ui.edits;
  const diagnostics = last.diagnostics || [];

  const dialectList = h('div', { class: 'dialect-list' },
    ...state.cache.dialects.map((dialect) => h('button', {
      class: 'dialect-item' + (dialect.key === state.ui.target ? ' is-active' : ''),
      type: 'button',
      disabled: dialect.status !== 'ready',
      title: dialect.note || (dialect.status === 'ready'
        ? 'render into ' + dialect.label
        : 'not implemented yet'),
      on: { click: () => pickTarget(dialect.key) },
    },
      h('span', { class: 'muted mono', text: dialect.status === 'ready' ? '\u25cf' : '\u25cb' }),
      h('span', {},
        h('span', { class: 'dialect-label', text: dialect.label }),
        h('span', { class: 'dialect-sub', text: dialect.language +
          (dialect.status === 'ready' ? '' : ' \u00b7 planned') })),
      dialect.carries_annotations
        ? badge('annotations', 'ok', 'this language carries the title, severity and ATT&CK mapping')
        : badge('query only', null, 'this language cannot carry title, severity or ATT&CK mapping'))));

  const pane = h('div', { class: 'stack' });
  if (stale && last.text) {
    pane.appendChild(h('div', { class: 'stale-note', text:
      'The rule has changed since this text was rendered. Press Render to see ' +
      'the rule as it is now \u2014 this is the PREVIOUS output.' }));
  }
  if (last.refusal) {
    /* A refusal EMPTIES the pane, as the card below promises. Leaving the
       previous language's text there, still labelled and still copyable, is
       how SPL gets pasted into a Sentinel deployment. */
    pane.appendChild(card({
      title: 'This target cannot write the rule',
      body: h('div', { class: 'stack' },
        h('div', { class: 'problem', style: { gridTemplateColumns: '110px minmax(0,1fr)' } },
          h('span', { class: 'problem-code', text: last.refusal.code }),
          h('div', { class: 'problem-plain', text: last.refusal.message })),
        h('p', { class: 'dim', text: 'Nothing was rendered, so there is nothing to ' +
          'copy. Choose another target, or change the rule.' })),
    }));
  } else {
    pane.appendChild(codeBlock({
      text: last.text || '\u2014',
      id: 'rendered',
      labelId: 'rendered-for',
      label: targetName(state.ui.target) + (last.target && last.target !== state.ui.target
        ? ' \u00b7 showing the previous target' : ''),
      copy: !!last.text,
    }));
  }


  if (diagnostics.length) {
    const notes = h('div', { class: 'stack' });
    for (const note of diagnostics) {
      notes.appendChild(h('div', {
        class: 'problem',
        style: { gridTemplateColumns: '92px minmax(0, 1fr)' },
      },
        h('span', { class: 'problem-code', text: note.code }),
        h('div', {},
          h('div', { class: 'problem-plain', text: note.message }),
          note.where ? h('div', { class: 'problem-engine', text: note.where }) : null,
          note.verified === false
            ? h('div', { class: 'problem-engine', text:
              'inferred from the rule, not measured against a sample' })
            : null)));
    }
    pane.appendChild(h('div', { id: 'diagnostics' }, card({
      title: diagnostics.length + ' thing(s) the target language does not say',
      sub: 'This text is not wrong; it is narrower or broader than the rule. ' +
        'Read these before deploying it.',
      body: notes,
    })));
  } else {
    pane.appendChild(h('div', { id: 'diagnostics' }));
  }

  const actions = h('div', { class: 'btn-row' },
    btn('Render', { kind: 'primary', id: 'render', onClick: doRender }),
    btn('Validate', { id: 'validate', onClick: doValidate }),
    btn('Copy', {
      /* Nothing to copy after a refusal, and copying text that belongs to a
         DIFFERENT target is the exact mistake this screen exists to prevent. */
      disabled: !last.text,
      title: last.text ? null : 'there is no rendered text to copy',
      onClick: async () => {
        if (!last.text) return;
        try {
          await navigator.clipboard.writeText(last.text);
          toast('Copied the rendered rule.', 'good');
        } catch (err) {
          toast('The browser refused clipboard access; select the text instead.', 'bad');
        }
      },
    }));

  return page('Preview', {
    eyebrow: 'Step 5 of 6 \u00b7 author',
    sub: 'The same rule, written in the language a particular SIEM accepts. ' +
      'Change the target on the left; the text changes, the rule does not.',
    actions,
    body: h('div', { class: 'stack-lg' },
      h('div', { class: 'author-col' },
        card({
          title: 'Target language',
          sub: state.cache.dialects.filter((d) => d.status === 'ready').length +
            ' of ' + state.cache.dialects.length + ' are implemented.',
          body: dialectList,
        }),
        h('div', { class: 'stack' }, pane, refusalNote())),
      stepFooter('preview'))});
}

function refusalNote() {
  return card({
    title: 'What a refusal means',
    body: h('div', { class: 'stack' },
      h('p', { class: 'dim' },
        'When the rule cannot be expressed in the target language, this pane ' +
        'is emptied and the reason is shown. It is never a best-effort ' +
        'translation: a rule that quietly matches more than you meant is ' +
        'worse than no rule at all.'),
      h('p', { class: 'dim' },
        'Validate lints the rule itself — including a screen for patterns ' +
        'that would hang the engine that runs it.')),
  });
}

function targetName(key) {
  const found = state.cache.dialects.find((d) => d.key === key);
  return found ? found.label + ' (' + found.language + ')' : key;
}

function pickTarget(key) {
  if (key === state.ui.target) return;
  setTarget(key);
}

export function doRender() {
  const target = state.ui.target;
  const serial = state.ui.serial;
  const edits = state.ui.edits;
  last = Object.assign({}, last, { requested: target, serial });
  attempt(async () => {
    let data = null;
    let refusal = null;
    try {
      data = await api.render(target, state.doc.payload);
    } catch (err) {
      refusal = {
        code: err.code || 'RENDER', message: err.message, where: err.where,
      };
    }
    /* If the target changed while this was in flight, showing the answer to
       the old question under the new label is the lie this screen exists to
       prevent. The same goes for the rule being replaced. */
    if (target !== state.ui.target || serial !== state.ui.serial) return;
    if (refusal) {
      last = {
        text: '', target, requested: target, serial, edits,
        diagnostics: [], refusal,
      };
    } else {
      last = {
        text: data.text,
        target,
        requested: target,
        serial,
        edits,
        diagnostics: data.diagnostics || [],
        refusal: null,
      };
    }
    rerender();
  }, { context: 'preview' });
}

function doValidate() {
  attempt(async () => {
    const data = await api.validate(state.doc.payload);
    if (data.outline) {
      state.cache.lastOutline = data.outline;
    }
    if (data.ok === false) {
      /* The engine answers with what is wrong; saying "sound" over the top of
         it is the failure mode this whole screen is about. */
      toast('Validate did not pass. Read the problems panel before deploying ' +
        'this rule.', 'bad');
      return;
    }
    toast('The rule is structurally sound and no pattern in it would hang the ' +
      'engine that runs it.', 'good');
  }, { context: 'preview' });
}
