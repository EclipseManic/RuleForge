/* Home — the whole tool in brief.

   This is the page you read before you work: what the tool is, the rule in
   eight languages, what it costs you to run, and the four things it does.
   Everything here is live — the code card renders the rule that is actually
   in the editor, and the dialect tabs re-render it — because a landing page
   that shows a screenshot goes stale the moment the engine changes. */

import { h } from '../ui/dom.js';
import { btn } from '../ui/components.js';
import { state, rerender, setTarget } from '../core/state.js';
import { go } from '../core/router.js';
import { TEMPLATES } from '../core/ir.js';
import { loadTemplate, startBlank } from './shared.js';
import * as api from '../core/api.js';

/* Short names for the tabs: two dialects are called "KQL", and a tab row that
   reads KQL twice is a question, not a label. */
const SHORT = {
  sigma: 'Sigma',
  spl: 'Splunk SPL',
  sentinel: 'Sentinel KQL',
  qradar: 'QRadar AQL',
  elastic: 'Elastic EQL',
  wazuh: 'Wazuh XML',
  chronicle: 'SecOps YARA-L',
  crowdstrike: 'Falcon FQL',
};

let last = { target: null, serial: -1, text: '', ok: true, explained: false };

export function render(route, fresh) {
  /* `serial` changes when the rule is replaced (a template, a version) as well
     as when it is edited, so the card cannot keep showing the previous rule. */
  if (fresh || last.target !== state.ui.target || last.serial !== state.ui.serial) {
    requestRender();
  }

  return h('div', { class: 'home' },
    h('section', { class: 'home-hero' },
      h('span', { class: 'hero-orb hero-orb--a', 'aria-hidden': 'true' }),
      h('span', { class: 'hero-orb hero-orb--b', 'aria-hidden': 'true' }),
      heroCopy(),
      h('div', { class: 'hero-visual' }, codeCard())),
    statsRow(),
    workflow(),
    templateSection(),
    claims(),
    cta(),
    h('div', { class: 'home-foot' },
      'RuleForge runs on this machine, with no account and no network calls ' +
      'off the loopback interface.',
      h('span', { class: 'home-foot-sep', text: '\u00b7' }),
      h('a', { href: '#/studio/health', text: 'Health' }),
      h('span', { class: 'home-foot-sep', text: '\u00b7' }),
      h('a', { href: '/classic', target: '_blank', rel: 'noreferrer', text: 'The previous interface' })));
}

/* -- hero ----------------------------------------------------------------- */

function heroCopy() {
  return h('div', { class: 'hero-copy' },
    h('span', { class: 'eyebrow hero-eyebrow' },
      h('span', { class: 'hero-dot', 'aria-hidden': 'true' }),
      'Local detection workbench'),
    h('h1', { class: 'hero-title' },
      'A workbench for ', h('em', {}, 'detection rules.')),
    h('p', { class: 'hero-lead' },
      'Write a rule once and read it in eight SIEM languages. Test it against ' +
      'real log lines before it goes anywhere near production. Everything runs ' +
      'on this machine \u2014 nothing is uploaded, and there is nothing to install.'),
    h('div', { class: 'hero-actions' },
      btn('Open a worked example', {
        kind: 'primary',
        id: 'home-example',
        onClick: () => loadTemplate(TEMPLATES[0]),
      }),
      btn('Start from nothing', {
        id: 'home-blank',
        onClick: startBlank,
      })),
    h('p', { class: 'hero-note' },
      'New to this? Take the example. It is a real credential-access rule, ' +
      'already filled in, and you can watch it change language as you switch ' +
      'the dialect in the card beside this.'));
}

/* -- the live code card --------------------------------------------------- */

function codeCard() {
  const rule = state.doc.payload.rule;
  const ready = state.cache.dialects.filter((d) => d.status === 'ready');

  const tabs = h('div', { class: 'code-tabs', id: 'home-dialects' },
    ...(ready.length
      ? ready.map((dialect) => h('button', {
        class: 'code-tab' + (dialect.key === state.ui.target ? ' is-active' : ''),
        type: 'button',
        title: 'render into ' + dialect.label + ' \u00b7 ' + dialect.language,
        on: { click: () => pick(dialect.key) },
      }, SHORT[dialect.key] || dialect.language))
      : [h('span', { class: 'muted', text: 'loading the dialect list\u2026' })]));

  const body = h('pre', { class: 'code-body', id: 'home-code' });
  body.appendChild(highlight(last.text || '\u2014'));

  return h('aside', { class: 'code-card', 'aria-label': 'The rule, rendered' },
    h('div', { class: 'code-card-head' },
      h('span', { class: 'traffic', 'aria-hidden': 'true' },
        h('i', {}), h('i', {}), h('i', {})),
      h('span', { class: 'code-name', text: rule.rule_id.v || 'untitled-rule' }),
      h('span', { class: 'code-flag' },
        h('span', { class: 'pulse', 'aria-hidden': 'true' }), 'local')),
    tabs,
    body,
    h('div', { class: 'code-foot' },
      checks(),
      h('span', { class: 'grow' }),
      h('span', { class: 'code-hint', text: ready.length + ' dialects \u00b7 refusals named, never guessed' })));
}

/** The ticks are a claim about a real request. When a render was refused, the
    card says so instead of tick marks. The \u2713 itself is drawn by CSS, so the
    row stays one line of text. */
function checks() {
  if (!last.ok) {
    return h('span', {
      class: 'code-check code-check--bad',
      text: 'could not render into ' + (SHORT[last.target] || last.target),
    });
  }
  /* "explained" used to be a tick nothing ever checked: the card only ever
     asked /api/render. It is now the answer to a real /api/outline request. */
  return h('span', { class: 'code-checks' },
    h('span', { class: 'code-check', text: 'parsed' }),
    last.explained
      ? h('span', { class: 'code-check', text: 'explained' })
      : h('span', {
        class: 'code-check code-check--bad',
        text: 'not explained',
        title: 'the outline request failed, so nothing read this rule back',
      }),
    h('span', { class: 'code-check', text: 'rendered' }));
}

/* -- colouring the card ---------------------------------------------------

   Three colours and no lexer: a line that starts with a comment marker is a
   comment, quoted text is a string, and a word is a key when a comparison or a
   colon follows it (or when it is a word these languages use as syntax).
   Anything else stays body text, so the worst a missing rule can do is leave a
   word uncoloured. */

const KEYWORDS = new Set((
  'and or not where project extend summarize sort order by take top limit ' +
  'select from like group having union all as on join let search eval stats ' +
  'table head fields rename dedup chart timechart count distinct index ' +
  'sourcetype earliest latest contains contains_cs startswith endswith matches ' +
  'has has_any has_all in is null true false match regex field rule events ' +
  'keys emit condition detection logsource selection timeframe product ' +
  'category level title id author description severity meta outcome ' +
  'if_sid if_matched_sid program_name same_source_ip if_group'
).split(' '));

const COMMENT_START = /^(\/\/|#|--|\/\*|\*|```|<!--)/;
const TOKEN = /("[^"]*"|'[^']*')|([A-Za-z_$][\w.$-]*)|(<\/?[A-Za-z_:][\w:.-]*)/g;

function highlight(text) {
  const frag = document.createDocumentFragment();
  const lines = String(text).split('\n');
  lines.forEach((line, index) => {
    frag.appendChild(highlightLine(line));
    if (index < lines.length - 1) frag.appendChild(document.createTextNode('\n'));
  });
  return frag;
}

function highlightLine(line) {
  if (COMMENT_START.test(line.trim())) {
    return h('span', { class: 't-comment' }, line || ' ');
  }
  const parts = [];
  let at = 0;
  TOKEN.lastIndex = 0;
  let match = TOKEN.exec(line);
  while (match) {
    if (match.index > at) parts.push(document.createTextNode(line.slice(at, match.index)));
    const value = match[0];
    if (match[1]) {
      parts.push(h('span', { class: 't-str' }, value));
    } else if (match[3]) {
      parts.push(h('span', { class: 't-key' }, value));
    } else {
      const rest = line.slice(match.index + value.length);
      const isKey = /^\s*(?:==|!=|<=|>=|:|=|>|<)/.test(rest);
      parts.push(isKey || KEYWORDS.has(value.toLowerCase())
        ? h('span', { class: 't-key' }, value)
        : document.createTextNode(value));
    }
    at = match.index + value.length;
    match = TOKEN.exec(line);
  }
  if (at < line.length) parts.push(document.createTextNode(line.slice(at)));
  return h('span', {}, ...parts);
}

async function requestRender() {
  const target = state.ui.target;
  const serial = state.ui.serial;
  /* Claimed before the await: a re-render while this is in flight must not
     start a second identical request. */
  last = { target, serial, text: last.text, ok: last.ok, explained: false };
  let answer = null;
  let explained = false;
  try {
    answer = await api.render(target, state.doc.payload);
    /* The card prints an "explained" tick, so it has to ask. A rule that
       renders but cannot be outlined is a real state, and the card used to
       claim otherwise. */
    try {
      await api.outline(state.doc.payload);
      explained = true;
    } catch (err) {
      explained = false;
    }
  } catch (err) {
    /* A refusal is already written on the card's own footer, in the language
       the reader is looking at. Raising it as a global problem and a toast on
       top of that covers the page for someone who only switched a tab. */
    answer = null;
  }
  if (target !== state.ui.target || serial !== state.ui.serial) return;
  if (answer) {
    last = { target, serial, text: answer.text, ok: true, explained };
    paint(answer.text);
    return;
  }
  /* The card must not go on claiming the rule was parsed and rendered. */
  last = { target, serial, text: last.text, ok: false, explained: false };
  paint(last.text || 'The rule could not be rendered into ' + target + '.');
}

function paint(text) {
  const node = document.getElementById('home-code');
  if (!node) return;
  node.replaceChildren(highlight(text));
  const foot = node.parentNode.querySelector('.code-foot');
  if (foot && foot.firstChild) foot.replaceChild(checks(), foot.firstChild);
}

function pick(key) {
  if (key === state.ui.target) return;
  /* Through setTarget, not straight into the state: the top-bar select, the
     status bar and the saved draft all read this one value. */
  setTarget(key);
  rerender();
}

/* -- the numbers ---------------------------------------------------------- */

function statsRow() {
  const ready = state.cache.dialects.filter((d) => d.status === 'ready').length;
  const stats = [
    [ready ? String(ready) : '\u2014', 'SIEM dialects'],
    ['0', 'Dependencies'],
    ['4', 'Workflows'],
    ['100%', 'Local \u2014 nothing uploaded'],
  ];
  return h('section', { class: 'stats', 'aria-label': 'What this is' },
    ...stats.map(([value, label]) => h('div', { class: 'stat' },
      h('strong', { text: value }),
      h('span', { text: label }))));
}

/* -- the four things ------------------------------------------------------ */

const WORKFLOWS = [
  {
    title: 'Author',
    body: 'Six screens in one order: name it, say where events come from, add ' +
      'the conditions, choose the stages, read it in the target language, test it.',
    to: 'details',
    action: 'Open Author',
  },
  {
    title: 'Test',
    body: 'Three verdicts, not two: matched, no match, and could not tell. Every ' +
      'stage shows which columns survived, so a wrong answer has an address.',
    to: 'test',
    action: 'Test a rule',
  },
  {
    title: 'Keep the evidence',
    body: 'Datasets, receipts and history. Every answer is stored with the rule ' +
      'and dataset hashes it was produced from, so it can be checked later.',
    to: 'datasets',
    action: 'Open Datasets',
  },
  {
    title: 'Bring a rule in',
    body: 'Paste a rule someone else wrote and get back what it really says, or ' +
      'draft one from your own log lines and see which fields are stable.',
    to: 'explain',
    action: 'Explain a rule',
  },
];

function workflow() {
  return h('section', { class: 'home-section' },
    h('div', { class: 'home-inner' },
      h('span', { class: 'eyebrow', text: 'The workflow' }),
      h('h2', { class: 'section-title', text: 'Four things, in the order you need them.' }),
      h('div', { class: 'workflow' },
        ...WORKFLOWS.map((item, index) => h('div', { class: 'workflow-card' },
          h('div', { class: 'workflow-head' },
            h('span', { class: 'workflow-num', text: String(index + 1).padStart(2, '0') }),
            h('strong', { text: item.title })),
          h('p', { text: item.body }),
          h('button', {
            class: 'link-btn',
            type: 'button',
            on: { click: () => go(item.to) },
          }, item.action, ' \u2192'))))));
}

/* -- templates ------------------------------------------------------------ */

function templateSection() {
  return h('section', { class: 'home-section home-section--quiet' },
    h('div', { class: 'home-inner' },
      h('div', { class: 'section-head' },
        h('div', {},
          h('span', { class: 'eyebrow', text: 'Start from a working rule' }),
          h('h2', { class: 'section-title', text: 'Load one, then change it.' })),
        h('span', { class: 'muted', text: 'Every template is parsed by the engine before it loads.' })),
      h('div', { class: 'templates' },
        ...TEMPLATES.map(templateCard))));
}

function templateCard(template) {
  return h('button', {
    class: 'template',
    type: 'button',
    title: 'Load "' + template.title + '" into the editor',
    on: { click: () => loadTemplate(template) },
  },
    h('span', { class: 'template-title', text: template.title }),
    h('span', { class: 'template-body', text: template.body }),
    h('span', { class: 'template-lang', text: 'KQL \u00b7 editable after loading' }));
}

/* -- what it refuses to do ------------------------------------------------ */

/** The promises, stated as refusals: they are the reason the tool is built the
    way it is, and they are the only claims on this page that a user can check
    from inside the app. */
function claims() {
  const ready = state.cache.dialects.filter((d) => d.status === 'ready');
  return h('section', { class: 'home-section home-section--quiet' },
    h('div', { class: 'home-inner' },
      h('span', { class: 'eyebrow', text: 'Why it is built this way' }),
      h('h2', { class: 'section-title', text: 'What it refuses to do.' }),
      h('div', { class: 'claims' },
        h('div', { class: 'claim' },
          h('h3', { text: 'Refuse rather than guess' }),
          h('p', {}, 'When a rule cannot be expressed in the language you asked ' +
            'for, you get a sentence explaining what would have gone wrong \u2014 ' +
            'not a best-effort translation that quietly matches more than you meant.')),
        h('div', { class: 'claim' },
          h('h3', { text: 'Three answers, not two' }),
          h('p', {}, 'A test returns ', h('em', { text: 'matched' }), ', ',
            h('em', { text: 'no match' }), ', or ', h('em', { text: 'could not tell' }),
            '. The third matters: a rule testing a field your sample does not ' +
            'contain has not failed to match \u2014 the question was never answered.')),
        h('div', { class: 'claim' },
          h('h3', { text: 'Eight languages, one rule' }),
          h('p', { text: 'The same rule, read back in each dialect it can be ' +
            'written in. Both directions, in one place.' }),
          h('div', { class: 'claim-langs' },
            ...(ready.length
              ? ready.map((dialect) => h('span', {
                class: 'badge',
                text: SHORT[dialect.key] || dialect.language,
              }))
              : [h('span', { class: 'muted', text: 'loading\u2026' })]))))));
}

/* -- the way in ----------------------------------------------------------- */

function cta() {
  return h('section', { class: 'home-cta' },
    h('div', { class: 'home-cta-copy' },
      h('h3', { text: 'Start in the Studio' }),
      h('p', { text: 'Seven tools under one tab: author the rule step by step, ' +
        'explain somebody else\u2019s, propose one from log lines, keep the ' +
        'datasets and receipts that back it, and read every version back.' })),
    h('div', { class: 'home-cta-actions' },
      btn('Open the Studio', {
        kind: 'primary',
        onClick: () => go('details'),
      }),
      btn('Browse datasets', {
        onClick: () => go('datasets'),
      })),
    h('div', { class: 'home-signature' },
      'RuleForge', h('span', { text: 'local build' })));
}

