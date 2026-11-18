/* The one state object.

   The DOM never owns truth. Every edit lands here first, and the screen is
   redrawn from here. `mutate` is for typing (state changes, screen does not
   re-render, so the caret stays put); `act` is for buttons (state changes and
   the screen is redrawn). */

import { emptyRule } from './ir.js';

const DRAFT_KEY = 'ruleforge.draft.v1';
const DRAFT_VERSION = 1;

export const state = {
  doc: {
    payload: emptyRule(),   // exactly what the API calls `rule`
    ruleId: 'draft',
    provenance: 'sentinel', // the dialect it came FROM
    entryId: null,
    parentId: null,
    origin: 'authored',
    sourceText: '',
    sample: { text: '', format: 'jsonl' },
  },
  ui: {
    screen: 'home',
    target: 'sentinel',
    dirty: false,
    busy: false,
    edits: 0,
    serial: 0,
    problems: [],
    lastRequest: null,
    lastResponse: null,
    inspected: null,
    inspectorOpen: false,
  },
  status: { health: null, lastVerdict: null, ruleHash: null, datasetHash: null },
  cache: {
    dialects: [],
    datasets: [],
    runs: [],
    versions: [],
    /* The operator list and every code the engine raises, fetched once from
       `/api/vocabulary`. A fourth copy of the operator list in the page is
       what let `has` exist in one place and not another. */
    vocabulary: { operators: [], codes: [] },
  },
  draftSavedAt: null,
};

let renderer = () => {};
const chromeListeners = [];

export function setRenderer(fn) {
  renderer = fn;
}

export function onChrome(fn) {
  chromeListeners.push(fn);
}

function persist() {
  /* A blank rule is not work. Writing it to the draft slot would make the next
     visit open on a placeholder instead of the worked example, which is how the
     landing page ended up advertising an empty rule. */
  if (isBlankDoc(state.doc)) {
    discardDraft();
    return;
  }
  try {
    localStorage.setItem(DRAFT_KEY, JSON.stringify({
      v: DRAFT_VERSION,
      at: new Date().toISOString(),
      doc: state.doc,
      target: state.ui.target,
    }));
    state.draftSavedAt = new Date().toISOString();
  } catch (err) {
    /* A full or blocked localStorage must not break editing. The draft is a
       convenience; the engine's store is the record. */
  }
}

let persistTimer = null;
function schedulePersist() {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    persistTimer = null;
    persist();
  }, 400);
}

/** Load a draft saved by a previous session, if there is one. */
/** A draft that is byte-identical to the starter rule holds nothing anyone
    typed: it is the scaffold, not work. */
export function isBlankDoc(doc) {
  try {
    return JSON.stringify(doc.payload) === JSON.stringify(emptyRule());
  } catch (err) {
    return false;
  }
}

export function restoreDraft() {
  let raw = null;
  try {
    raw = localStorage.getItem(DRAFT_KEY);
  } catch (err) {
    return false;
  }
  if (!raw) return false;
  try {
    const saved = JSON.parse(raw);
    if (!saved || saved.v !== DRAFT_VERSION || !saved.doc || !saved.doc.payload) {
      return false;
    }
    if (isBlankDoc(saved.doc)) {
      /* Older builds stored the blank starter. Discard it rather than restore
         an empty rule over the example. */
      discardDraft();
      return false;
    }
    state.doc = Object.assign(state.doc, saved.doc);
    if (saved.target) state.ui.target = saved.target;
    state.draftSavedAt = saved.at || null;
    return true;
  } catch (err) {
    return false;
  }
}

export function discardDraft() {
  try {
    localStorage.removeItem(DRAFT_KEY);
  } catch (err) { /* nothing to remove */ }
  state.draftSavedAt = null;
}

/** Change state without redrawing the current screen. */
export function mutate(fn) {
  fn(state);
  state.ui.dirty = true;
  state.ui.edits += 1;
  state.ui.serial += 1;
  schedulePersist();
  for (const listener of chromeListeners) listener(state);
}

/** Change state that is not the rule: the saved sample, a filter box. It is
    persisted with the draft but does not mark the rule unsaved, because the
    rule did not change. */
export function mutateQuiet(fn) {
  fn(state);
  schedulePersist();
}

/** Change state and redraw. */
export function act(fn) {
  mutate(fn);
  renderer();
}

export function rerender() {
  renderer();
}

/* The target language is one global choice shown in the top bar. Mirrors of it
   (the select, Home's tabs, Preview's list) must never disagree, so they all
   write through here and everything that displays it listens. */
const targetListeners = new Set();

export function onTargetChange(fn) {
  targetListeners.add(fn);
  return () => targetListeners.delete(fn);
}

export function setTarget(key) {
  if (!key || state.ui.target === key) return;
  state.ui.target = key;
  schedulePersist();
  for (const listener of targetListeners) listener(key);
}

/** An edit made directly on the IR (the condition and stage editors mutate
    nodes in place): record it without redrawing the screen under the caret. */
export function touch() {
  mutate(() => {});
}

/** Replace the rule being edited, from a template, an import, a version. */
export function loadRule({ payload, provenance, origin, sourceText, entryId, parentId }) {
  state.doc.payload = payload;
  state.doc.provenance = provenance || state.ui.target;
  state.doc.origin = origin || 'authored';
  state.doc.sourceText = sourceText || '';
  state.doc.entryId = entryId ?? null;
  state.doc.parentId = parentId ?? null;
  state.doc.ruleId = payload && payload.rule && payload.rule.rule_id
    ? payload.rule.rule_id.v : 'draft';
  state.ui.dirty = false;
  state.ui.serial += 1;
  state.status.lastVerdict = null;
  /* The rows and the trace belong to the rule that produced them. Leaving them
     in place put rule A's evidence on the Test screen under rule B. */
  state.status.lastResult = null;
  state.status.staleVerdict = false;
  schedulePersist();
}

export const doc = () => state.doc.payload.rule;

export const stages = () => doc().pipeline.v;

export const stageById = (id) => stages().find((s) => s.id.v === id) || null;

export function conditions() {
  return stages().filter((s) => s['@'] === 'Filter');
}

export function nextStageId(kind) {
  const base = String(kind).toLowerCase();
  let index = stages().length;
  let candidate = base + '_' + index;
  const taken = new Set(stages().map((s) => s.id.v));
  while (taken.has(candidate)) {
    index += 1;
    candidate = base + '_' + index;
  }
  return candidate;
}
