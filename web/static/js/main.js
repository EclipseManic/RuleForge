/* Entry point: build the shell, restore the draft, route. */

import {
  state, setRenderer, restoreDraft, rerender, onChrome, loadRule,
} from './core/state.js';
import { TEMPLATES } from './core/ir.js';
import { parse, byName } from './core/router.js';
import { attempt, setNotifier, problemFromError } from './core/problems.js';
import { toast } from './ui/components.js';
import { bindShell, refreshShell, refreshEditing } from './ui/shell.js';
import { mount } from './ui/dom.js';
import * as api from './core/api.js';
import { saveVersionNow } from './screens/versions.js';

import * as home from './screens/home.js';
import * as details from './screens/details.js';
import * as source from './screens/source.js';
import * as conditions from './screens/conditions.js';
import * as stages from './screens/stages.js';
import * as preview from './screens/preview.js';
import * as test from './screens/test.js';
import * as datasets from './screens/datasets.js';
import * as receipts from './screens/receipts.js';
import * as versions from './screens/versions.js';
import * as explain from './screens/explain.js';
import * as draft from './screens/draft.js';
import * as reference from './screens/reference.js';
import * as health from './screens/health.js';

const SCREENS = {
  home, details, source, conditions, stages, preview, test,
  datasets, receipts, versions, explain, draft, reference, health,
};

let lastHash = null;

function render() {
  const hash = window.location.hash || '#/';
  const fresh = hash !== lastHash;
  lastHash = hash;
  const route = parse(hash);
  const screen = SCREENS[route.name] || SCREENS.home;
  state.ui.screen = route.name;

  const host = document.getElementById('screen');
  try {
    mount(host, screen.render(route, fresh));
    host.scrollTop = 0;
  } catch (err) {
    /* A screen that throws must not leave a blank page with no explanation. */
    const problem = problemFromError(err, route.name);
    problem.plain = 'The ' + byName(route.name).label + ' screen failed to ' +
      'build: ' + (err && err.message ? err.message : String(err));
    problem.fix = null;
    state.ui.problems.push(problem);
    mount(host, null);
    toast(problem.plain, 'bad', problem.code);
  }

  refreshShell(route);
  document.title = route.view === 'home'
    ? 'RuleForge \u2014 a workbench for detection rules'
    : byName(route.name).label + ' \u00b7 RuleForge';
}

setRenderer(render);
setNotifier((problem) => {
  toast(problem.plain, 'bad', problem.code);
});

window.addEventListener('hashchange', () => {
  render();
});

window.addEventListener('error', (event) => {
  const problem = problemFromError(event.error || event.message, 'page');
  problem.plain = 'An uncaught error stopped part of the page: ' +
    (event.message || 'unknown');
  state.ui.problems.push(problem);
  refreshShell();
});

window.addEventListener('unhandledrejection', (event) => {
  const problem = problemFromError(event.reason, 'page');
  state.ui.problems.push(problem);
  toast(problem.plain, 'bad', problem.code);
  refreshShell();
});

/* The status bar's health dot must reflect a real answer, and only a real
   answer. `onPing` is called on boot and every 20 seconds. */
async function ping() {
  try {
    const data = await api.health();
    state.status.health = !!data.ok;
  } catch (err) {
    state.status.health = false;
  }
  refreshShell();
}

/** A fresh session opens with the first template already loaded. An empty
    rule teaches nothing, and Home's card would otherwise advertise a blank
    query as the first thing anyone sees. */
async function seedExample() {
  const template = TEMPLATES[0];
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
    state.ui.target = template.dialect;
    rerender();
  }, { context: 'boot' });
}

function boot() {
  const restored = restoreDraft();
  bindShell({
    onSaveVersion: () => saveVersionNow(),
    onPing: () => ping(),
    onTargetChange: () => rerender(),
  });
  if (!window.location.hash) window.location.hash = '#/';
  render();
  if (!restored) seedExample();

  attempt(async () => {
    const data = await api.dialects();
    state.cache.dialects = data.dialects || [];
    const ready = state.cache.dialects.find((d) => d.status === 'ready');
    if (ready && !state.cache.dialects.some((d) => d.key === state.ui.target)) {
      state.ui.target = ready.key;
    }
    rerender();
  }, { context: 'boot' });

  /* The Studio tabs show how much evidence exists, so the counts are fetched
     once at start rather than on every navigation. */
  attempt(async () => {
    const [datasets, runs, versions] = await Promise.all([
      api.datasets(''),
      api.testRuns(),
      api.history({ limit: 100 }),
    ]);
    state.cache.datasets = datasets.datasets || [];
    state.cache.runs = runs.test_runs || [];
    state.cache.versions = versions.entries || [];
    refreshShell();
  }, { context: 'boot' });

  /* The operator list and the code list come from the engine, never from a
     copy pasted into this page. */
  attempt(async () => {
    const data = await api.vocabulary();
    state.cache.vocabulary = {
      operators: data.operators || [],
      codes: data.codes || [],
    };
    refreshShell();
  }, { context: 'boot' });

  onChrome(() => {
    /* The rule bar and status bar follow every edit without redrawing the
       screen, so typing never loses the caret. */
    refreshEditing();
  });
}

boot();
