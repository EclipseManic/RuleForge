/* The frame around every screen: the top bar (Home / Studio, target, save), the
   Studio tab row, the Author bar (rule identity + the six steps), the Problems
   panel, the status bar and the state inspector. */

import { h, fmtTime } from './dom.js';
import { btn } from './components.js';
import { state, rerender, setTarget, onTargetChange } from '../core/state.js';
import {
  SCREENS, STEPS, TOOLS, CORNER, byName, parse, go, isStep,
} from '../core/router.js';
import { applyFix, dismissProblem } from '../core/problems.js';

let route = parse(window.location.hash);

/* -- top bar -------------------------------------------------------------- */

/** Home and Studio are views, not screens: exactly one of them is lit. */
export function refreshMainNav() {
  const host = document.querySelector('#mainnav');
  if (!host) return;
  const active = route.view === 'home' ? 'home' : 'studio';
  for (const link of host.querySelectorAll('a[data-nav]')) {
    link.classList.toggle('is-active', link.dataset.nav === active);
    if (link.dataset.nav === active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

/** Health is a screen about the installation, so its door is in the top bar
    beside Save rather than among the Studio's tools. */
export function refreshHealthLink() {
  const link = document.querySelector('#health-link');
  if (!link) return;
  const active = route.name === CORNER[0].name;
  link.classList.toggle('is-active', active);
  if (active) link.setAttribute('aria-current', 'page');
  else link.removeAttribute('aria-current');
}

/** The Studio's own tabs. Health is not one of them: it describes the
    installation, not the rule, so it lives in the top bar beside Save. */
export function refreshSubnav() {
  const host = document.querySelector('#subnav');
  if (!host) return;
  const inStudio = route.view === 'studio';
  host.hidden = !inStudio;
  if (!inStudio) { host.textContent = ''; return; }

  host.textContent = '';
  const tab = (entry, active) => h('button', {
    class: 'tab' + (active ? ' is-active' : ''),
    type: 'button',
    'aria-current': active ? 'page' : null,
    title: entry.label,
    on: { click: () => go(entry.name) },
  }, entry.label);

  host.appendChild(tab({ name: 'details', label: 'Author' }, isStep(route.name)));

  const counts = {
    datasets: state.cache.datasets.length,
    receipts: state.cache.runs.length,
    versions: state.cache.versions.length,
  };
  for (const tool of TOOLS) {
    host.appendChild(h('button', {
      class: 'tab' + (route.name === tool.name ? ' is-active' : ''),
      type: 'button',
      'aria-current': route.name === tool.name ? 'page' : null,
      on: { click: () => go(tool.name) },
    },
      tool.label,
      counts[tool.name]
        ? h('span', { class: 'tab-count', text: String(counts[tool.name]) })
        : null));
  }

}

/** The target language is the one global choice: what the rule is written out
    as. It lives in the top bar, so it is visible from every screen. */
export function refreshTargetSelect() {
  const select = document.querySelector('#target');
  if (!select) return;
  const ready = state.cache.dialects.filter((d) => d.status === 'ready');
  select.textContent = '';
  if (!ready.length) {
    select.appendChild(h('option', { value: state.ui.target, text: 'loading\u2026' }));
    select.disabled = true;
    return;
  }
  select.disabled = false;
  for (const dialect of ready) {
    select.appendChild(h('option', {
      value: dialect.key,
      text: dialect.label + ' (' + dialect.language + ')',
    }));
  }
  select.value = state.ui.target;
}

/* -- author bar ----------------------------------------------------------- */

/** Inside Author the six steps replace a menu: the order is the workflow, and
    the two ways forward are the step row here and the buttons at the bottom of
    each screen. */
export function refreshSteps() {
  const host = document.querySelector('#steps');
  const bar = document.querySelector('#authorbar');
  if (!host || !bar) return;
  const onStep = isStep(route.name);
  bar.hidden = !onStep;
  if (!onStep) { host.textContent = ''; return; }

  host.textContent = '';
  const currentStep = byName(route.name).step || 0;
  for (const screen of STEPS) {
    const isDone = screen.step < currentStep;
    host.appendChild(h('button', {
      class: 'step' + (screen.name === route.name ? ' is-current' : '') +
        (isDone ? ' is-done' : ''),
      type: 'button',
      'aria-current': screen.name === route.name ? 'step' : null,
      on: { click: () => go(screen.name) },
    },
      h('span', { class: 'step-num', text: String(screen.step) }),
      screen.label));
    if (screen.step < STEPS.length) {
      host.appendChild(h('span', { class: 'step-arrow', text: '\u203a' }));
    }
  }
}

export function refreshRuleBar() {
  const host = document.querySelector('#rulebar');
  if (!host) return;
  host.textContent = '';
  const rule = state.doc.payload && state.doc.payload.rule;
  const title = rule && rule.annotations.title.v;
  const name = title || (rule ? rule.rule_id.v : 'untitled');
  const filters = rule
    ? rule.pipeline.v.filter((s) => s['@'] === 'Filter').length : 0;

  host.appendChild(h('span', { class: 'rulebar-title', text: name, title: name }));
  /* One rule, one identity: repeating the id because the title is empty read
     as two different rules side by side. */
  const parts = [];
  if (title && rule && title !== rule.rule_id.v) parts.push(rule.rule_id.v);
  parts.push(filters + (filters === 1 ? ' condition' : ' conditions'));
  host.appendChild(h('span', { class: 'rulebar-meta', text: parts.join(' \u00b7 ') }));
  if (state.ui.dirty) {
    host.appendChild(h('span', { class: 'dirty-dot', title: 'unsaved changes' }));
    host.appendChild(h('span', { class: 'rulebar-meta', text: 'unsaved' }));
  }
}

/* -- problems ------------------------------------------------------------- */

const SEVERITY_ORDER = { error: 0, warning: 1, caution: 2, info: 3 };

export function refreshProblems() {
  const host = document.querySelector('#problems');
  if (!host) return;
  const problems = state.ui.problems.slice().sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
  );
  host.dataset.empty = problems.length ? 'false' : 'true';
  host.textContent = '';
  if (!problems.length) return;

  const collapsed = host.classList.contains('is-collapsed');
  host.appendChild(h('div', { class: 'problems-head' },
    h('span', {
      class: 'badge ' + (problems.some((p) => p.severity === 'error') ? 'danger' : 'caution'),
      text: problems.length + (problems.length === 1 ? ' problem' : ' problems'),
    }),
    h('span', { class: 'grow muted', text: collapsed ? 'hidden \u2014 show to read them' : '' }),
    btn(collapsed ? 'Show' : 'Hide', {
      size: 'sm', kind: 'quiet',
      onClick: () => {
        host.classList.toggle('is-collapsed');
        refreshProblems();
      },
    })));

  const body = h('div', { class: 'problems-body' });
  for (const problem of problems) {
    body.appendChild(h('div', { class: 'problem' },
      h('span', { class: 'problem-code', text: problem.code }),
      h('div', {},
        h('div', { class: 'problem-plain', text: problem.plain }),
        problem.message && problem.message !== problem.plain
          ? h('div', { class: 'problem-engine', text: problem.message + structuredSuffix(problem) })
          : null),
      h('div', { class: 'problem-fix row' },
        problem.fix
          ? btn(problem.fix.label + ' \u2192', {
            size: 'sm',
            onClick: () => applyFix(problem.fix),
          })
          : null,
        btn('\u00d7', {
          size: 'sm', kind: 'quiet', title: 'dismiss',
          onClick: () => dismissProblem(problem),
        }))));
  }
  host.appendChild(body);
}

/* -- status bar ----------------------------------------------------------- */

/** The condition a refusal was about, when the engine named one.

   `where` is a breadcrumb ("render", "parse"). `field`, `operator` and
   `alternatives` are the part an analyst can act on, and they were being
   dropped at the API boundary. */
function structuredSuffix(problem) {
  const parts = [];
  if (problem.condition) parts.push('condition: ' + problem.condition);
  else if (problem.field || problem.operator) {
    parts.push([problem.field, problem.operator].filter(Boolean).join(' '));
  }
  if (problem.node) parts.push('in ' + problem.node);
  if ((problem.alternatives || []).length) {
    parts.push('try instead: ' + problem.alternatives.join(', '));
  }
  return parts.length ? ' \u2014 ' + parts.join('; ') : '';
}

export function refreshStatusBar() {
  const host = document.querySelector('#statusbar');
  if (!host) return;
  host.textContent = '';

  const dialect = state.cache.dialects.find((d) => d.key === state.ui.target);
  const health = state.status.health;
  const healthState = health === null ? '' : (health ? ' dot--ok' : ' dot--bad');
  const verdict = state.status.lastVerdict;

  host.appendChild(h('span', { class: 'status-item' },
    h('span', { class: 'dot' + healthState }),
    h('b', { text: health === null ? 'checking' : (health ? 'server ok' : 'server down') })));

  host.appendChild(h('span', { class: 'status-item' },
    h('b', { text: 'target' }), dialect ? dialect.label : state.ui.target));

  host.appendChild(h('span', { class: 'status-item' },
    h('b', { text: 'rule' }),
    state.status.ruleHash ? String(state.status.ruleHash).slice(0, 8) : 'unsaved'));

  if (state.status.datasetHash) {
    host.appendChild(h('span', { class: 'status-item' },
      h('b', { text: 'dataset' }), String(state.status.datasetHash).slice(0, 8)));
  }

  host.appendChild(h('span', { class: 'status-item' },
    h('b', { text: 'verdict' }),
    state.status.staleVerdict
      ? 'stale \u2014 ' + (state.status.staleReason === 'rule' ? 'the rule changed' : 'the sample changed')
      : verdict === null ? 'not run'
        : ({ matched: 'matched', no_match: 'no match', not_evaluated: 'could not tell' }[verdict] || verdict)));

  host.appendChild(h('span', { class: 'status-spacer' }));

  if (state.draftSavedAt) {
    host.appendChild(h('span', { class: 'status-item' },
      h('b', { text: 'draft' }), fmtTime(state.draftSavedAt)));
  }
  host.appendChild(h('span', { class: 'status-item' },
    h('span', { class: 'dot' + (state.ui.busy ? ' dot--caution' : '') }),
    state.ui.busy ? 'working' : 'idle'));
}

/** The parts that follow an edit: the rule bar and the status bar. The tabs do
    not change while typing, and rebuilding them on every keystroke is wasted
    work that can steal focus. */
export function refreshEditing() {
  refreshRuleBar();
  refreshStatusBar();
}

export function refreshShell(nextRoute) {
  if (nextRoute) route = nextRoute;
  else route = parse(window.location.hash);
  const app = document.querySelector('.app');
  if (app) app.dataset.view = route.view;
  refreshMainNav();
  refreshHealthLink();
  refreshSubnav();
  refreshTargetSelect();
  refreshSteps();
  refreshRuleBar();
  refreshProblems();
  refreshStatusBar();
}

/* -- inspector ------------------------------------------------------------ */

export function openInspector() {
  const host = document.querySelector('#inspector');
  if (!host) return;
  host.hidden = false;
  host.textContent = '';
  const box = h('div', { class: 'inspector-box' },
    h('header', {},
      h('span', { class: 'eyebrow grow', text: 'State inspector' }),
      btn('Close', { size: 'sm', kind: 'quiet', onClick: closeInspector })),
    h('div', { class: 'inspector-body' },
      h('div', {},
        h('h3', { text: 'UI state' }),
        h('pre', { text: JSON.stringify({
          screen: state.ui.screen,
          target: state.ui.target,
          dirty: state.ui.dirty,
          problems: state.ui.problems.map((p) => p.code),
          draftsSavedAt: state.draftSavedAt,
        }, null, 2) })),
      h('div', {},
        h('h3', { text: 'The rule payload (what every request sends)' }),
        h('pre', { text: JSON.stringify(state.doc.payload, null, 2) })),
      h('div', {},
        h('h3', { text: 'Last request' }),
        h('pre', { text: JSON.stringify(state.ui.lastRequest, null, 2) })),
      h('div', {},
        h('h3', { text: 'Last response' }),
        h('pre', { text: JSON.stringify(state.ui.lastResponse, null, 2) }))));
  box.onclick = (event) => event.stopPropagation();
  host.appendChild(box);
  host.onclick = closeInspector;
}

export function closeInspector() {
  const host = document.querySelector('#inspector');
  if (host) host.hidden = true;
}

/* -- boot ----------------------------------------------------------------- */

export function bindShell(options) {
  const opts = options || {};

  document.querySelector('#save-version').onclick = () => opts.onSaveVersion();

  document.querySelector('#target').onchange = (event) => {
    setTarget(event.target.value);
  };

  /* Whichever control changes the target — this select, a dialect tab on Home,
     a dialect on Preview — every mirror of it updates, and the screen is
     redrawn against the new language. */
  onTargetChange(() => {
    refreshTargetSelect();
    refreshStatusBar();
    if (opts.onTargetChange) opts.onTargetChange();
  });

  document.addEventListener('keydown', (event) => {
    const mod = event.ctrlKey || event.metaKey;
    if (mod && event.shiftKey && event.key.toLowerCase() === 'd') {
      event.preventDefault();
      openInspector();
      return;
    }
    if (mod && event.key.toLowerCase() === 's') {
      event.preventDefault();
      opts.onSaveVersion();
      return;
    }
    if (event.key === 'Escape') {
      closeInspector();
    }
  });

  /* The health dot is only honest if it is recent. */
  const ping = () => opts.onPing();
  ping();
  setInterval(ping, 20000);

  refreshShell();
  /* A redraw, not an edit: booting the shell must not mark the rule unsaved. */
  rerender();
}

export { SCREENS };
