/* Hash router. Every screen is a URL, so a bug can be linked, reloaded and
   reproduced — the old UI had no addressable state at all.

   Two views, one bar: `Home` is the overview you read, `Studio` is the work.
   Inside Studio there are tools, and one of those tools — Author — is a
   sequence of six steps navigated in the page, not six entries in a menu. */

export const STEPS = [
  { name: 'details', label: 'Details', step: 1 },
  { name: 'source', label: 'Source', step: 2 },
  { name: 'conditions', label: 'Conditions', step: 3 },
  { name: 'stages', label: 'Stage library', step: 4 },
  { name: 'preview', label: 'Preview', step: 5 },
  { name: 'test', label: 'Test', step: 6 },
];

/* The Studio's tabs, left to right, exactly as they appear on screen. `path`
   is the URL segment; `name` is the module. They differ only for History,
   whose module is still called `versions` because that is what the store
   calls it. */
export const TOOLS = [
  { name: 'datasets', label: 'Datasets', path: 'datasets' },
  { name: 'receipts', label: 'Receipts', path: 'receipts' },
  { name: 'explain', label: 'Explain', path: 'explain' },
  { name: 'draft', label: 'Draft from logs', path: 'draft' },
  { name: 'versions', label: 'History', path: 'history' },
  { name: 'reference', label: 'Reference', path: 'reference' },
];

/* Pushed to the right end of the same row: it is about the installation, not
   about the rule. */
export const CORNER = [{ name: 'health', label: 'Health', path: 'health' }];

export const HOME = { name: 'home', label: 'Home', href: '#/' };

export const SCREENS = [
  HOME,
  ...STEPS.map((s) => ({
    name: s.name, label: s.label, step: s.step, group: 'AUTHOR',
  })),
  ...TOOLS.map((t) => ({ name: t.name, label: t.label, group: 'STUDIO' })),
  ...CORNER.map((t) => ({ name: t.name, label: t.label, group: 'SYSTEM' })),
];

const STEP_NAMES = new Set(STEPS.map((s) => s.name));
const TOOL_BY_NAME = new Map([...TOOLS, ...CORNER].map((t) => [t.name, t]));
const TOOL_BY_PATH = new Map([...TOOLS, ...CORNER].map((t) => [t.path, t]));

/** Old URLs keep working: a link from the previous build, or a bookmark, must
    land on the screen it used to, never on a blank one. */
const LEGACY_PATHS = new Map([
  ['start', 'home'],
  ['datasets', 'datasets'],
  ['receipts', 'receipts'],
  ['versions', 'versions'],
  ['history', 'versions'],
  ['explain', 'explain'],
  ['draft', 'draft'],
  ['reference', 'reference'],
  ['health', 'health'],
]);

export function byName(name) {
  return SCREENS.find((s) => s.name === name) || SCREENS[0];
}

export const isStep = (name) => STEP_NAMES.has(name);

export function parse(hash) {
  const raw = String(hash || '').replace(/^#/, '');
  const [pathPart, queryPart] = raw.split('?');
  const path = pathPart.split('/').filter(Boolean);
  const query = new URLSearchParams(queryPart || '');

  if (!path.length || path[0] === 'home') return { name: 'home', view: 'home', query };

  /* #/rule/<id>/<step> was the previous build's shape. */
  if (path[0] === 'rule') {
    const step = STEP_NAMES.has(path[2]) ? path[2] : 'details';
    return { name: step, view: 'studio', ruleId: path[1] || 'draft', query };
  }

  if (path[0] === 'studio') {
    const rest = path.slice(1);
    if (!rest.length) return { name: 'details', view: 'studio', query };
    if (rest[0] === 'author') {
      const step = STEP_NAMES.has(rest[1]) ? rest[1] : 'details';
      return { name: step, view: 'studio', query };
    }
    const tool = TOOL_BY_PATH.get(rest[0]);
    if (tool) return { name: tool.name, view: 'studio', id: rest[1] || null, query };
    return { name: 'details', view: 'studio', query };
  }

  if (LEGACY_PATHS.has(path[0])) {
    const name = LEGACY_PATHS.get(path[0]);
    if (name === 'home') return { name, view: 'home', query };
    return { name, view: 'studio', id: path[1] || null, query };
  }

  return { name: 'home', view: 'home', query };
}

/** The URL for a screen. `draft` is replaced by the stored id only after a save. */
export function href(name, options) {
  const opts = options || {};
  if (name === 'home') return '#/';
  if (STEP_NAMES.has(name)) return '#/studio/author/' + name;
  const tool = TOOL_BY_NAME.get(name);
  if (tool) return '#/studio/' + tool.path + (opts.id ? '/' + opts.id : '');
  return '#/';
}

export function go(name, options) {
  const next = href(name, options);
  if (window.location.hash === next) {
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    return;
  }
  window.location.hash = next;
}

export const nextStepOf = (name) => {
  const index = STEPS.findIndex((s) => s.name === name);
  if (index < 0) return null;
  return STEPS[index + 1] || null;
};

export const previousStepOf = (name) => {
  const index = STEPS.findIndex((s) => s.name === name);
  if (index <= 0) return null;
  return STEPS[index - 1] || null;
};
