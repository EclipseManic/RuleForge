/* Every message in one place.

   A diagnostic the analyst cannot act on is noise, so each code here carries
   the sentence that explains it and the control that fixes it. Codes come from
   the engine verbatim; an unknown code falls back to the engine's own message
   and a link to the reference page rather than an invented explanation. */

import { state, rerender } from './state.js';

/** severity is honest: "could not tell" is never an error. */
const TABLE = {
  TIME_FIELD_NOT_FOUND: {
    plain: 'This rule counts events over time, but the source has no time ' +
      'field. Set one, or the count cannot be windowed.',
    fix: { label: 'Set the time field', href: '#/studio/author/source', focus: '#read-timefield' },
  },
  INDEX_TIME_FILTER: {
    plain: 'This rule narrows events in the SIEM\'s own index syntax, before ' +
      'any event is read. A local sample cannot reproduce that, so a test ' +
      'reports it instead of pretending.',
    fix: { label: 'See the selector', href: '#/studio/author/source', focus: '#read-selector' },
  },
  ANNOTATIONS_NOT_TRANSFERABLE: {
    plain: 'The target language cannot carry the title, severity and ATT&CK ' +
      'mapping. The query is correct; the paperwork is lost in translation.',
    fix: { label: 'Which languages carry it', href: '#/studio/reference' },
  },
  DECLARED_ONLY: {
    plain: 'This step is modelled and rendered, but only the vendor\'s own ' +
      'engine can actually run it. A local test cannot evaluate it.',
    fix: { label: 'See the step', href: '#/studio/author/stages' },
  },
  UNDECIDED: {
    plain: 'Something in the rule could not be decided from this sample, so ' +
      'the verdict is "could not tell" — not "no match".',
    fix: { label: 'Open the test', href: '#/studio/author/test' },
  },
  DEFAULT_TABLE: {
    plain: 'No source table was named, so a default was assumed. Name the ' +
      'table your SIEM actually reads.',
    fix: { label: 'Name the table', href: '#/studio/author/source', focus: '#read-table' },
  },
  SELECTOR_NOT_TRANSFERABLE: {
    plain: 'The index-time selector was dropped because the target language ' +
      'has no equivalent. The rendered rule matches MORE than this one.',
    fix: { label: 'See the selector', href: '#/studio/author/source', focus: '#read-selector' },
  },
  COMPARISON_UNDECIDABLE: {
    plain: 'One condition compares values the engine cannot order — a text ' +
      'value against a number, for instance. The row is undecided.',
    fix: { label: 'Open conditions', href: '#/studio/author/conditions' },
  },
  REGEX_INVALID: {
    plain: 'A pattern in this rule is not valid in the language being ' +
      'rendered. Fix the pattern before deploying it.',
    fix: { label: 'Open conditions', href: '#/studio/author/conditions' },
  },
  REGEX_CATASTROPHIC_BACKTRACKING: {
    plain: 'A pattern in this rule can hang the engine that runs it. Validate ' +
      'refused the rule rather than shipping it.',
    fix: { label: 'Open conditions', href: '#/studio/author/conditions' },
  },
  DIALECT_NOT_IMPLEMENTED: {
    plain: 'That language is listed but not implemented yet. Nothing is wrong ' +
      'with your rule.',
    fix: { label: 'See what is ready', href: '#/studio/reference' },
  },
  DIALECT_CANNOT_PARSE: {
    plain: 'That language can be rendered but cannot be read back, so a rule ' +
      'cannot be imported from it.',
    fix: { label: 'Language matrix', href: '#/studio/reference' },
  },
  REQUEST_EMPTY: {
    plain: 'There was nothing to send. Paste or type something first.',
  },
  REQUEST_FIELD_TYPE: {
    plain: 'The request had a field of the wrong type. This is a bug in the ' +
      'page, not in your rule.',
  },
  REQUEST_TOO_MANY_EVENTS: {
    plain: 'That sample has more events than one test accepts. Split it or use ' +
      'a saved dataset.',
    fix: { label: 'Open datasets', href: '#/studio/datasets' },
  },
  REQUEST_TOO_LARGE: {
    plain: 'The request body was larger than the server accepts. Split the ' +
      'sample.',
  },
  REQUEST_NOT_JSON: {
    plain: 'The page sent something the server could not read as JSON.',
  },
  CODEC_MALFORMED: {
    plain: 'The rule payload is not a shape this build can read.',
  },
  CODEC_SCHEMA_UNSUPPORTED: {
    plain: 'This rule was written by a different schema version. Reading it ' +
      'anyway would be guessing at what changed.',
  },
  STORE_DATASET_CORRUPT: {
    plain: 'A saved dataset could not be read back. The stored bytes are kept; ' +
      'nothing was deleted.',
    fix: { label: 'Open datasets', href: '#/studio/datasets' },
  },
  STORE_ENTRY_UNKNOWN: {
    plain: 'That version is not in the store. It may have been forgotten from ' +
      'another tab.',
    fix: { label: 'Open versions', href: '#/studio/history' },
  },
  STORE_PARENT_UNKNOWN: {
    plain: 'The version this was derived from is no longer stored, so the chain ' +
      'starts here.',
  },
  NOT_FOUND: {
    plain: 'The server does not serve that path.',
    fix: { label: 'Run the health check', href: '#/studio/health' },
  },
  PATH_OUTSIDE_STATIC: {
    plain: 'A static file request tried to leave the static directory and was ' +
      'refused.',
  },
  NETWORK: {
    plain: 'The page could not reach the workbench. Is `python run.py` still ' +
      'running in its terminal?',
    fix: { label: 'Run the health check', href: '#/studio/health' },
  },
  SERVER_ERROR: {
    plain: 'The server failed while answering. The traceback is in the terminal ' +
      'that started it.',
    fix: { label: 'Run the health check', href: '#/studio/health' },
  },
};

const SEVERITY_DEFAULT = 'error';

export function plainFor(code, fallbackMessage) {
  const entry = TABLE[code];
  return entry ? entry.plain : (fallbackMessage || code);
}

export function fixFor(code) {
  const entry = TABLE[code];
  return entry && entry.fix ? entry.fix : null;
}

export function knownCodes() {
  return Object.keys(TABLE).sort();
}

/** Turn anything thrown by the API layer into one Problem. */
export function problemFromError(err, context) {
  const code = err && err.code ? err.code : 'SERVER_ERROR';
  return {
    code,
    severity: err && err.severity ? err.severity : SEVERITY_DEFAULT,
    message: err && err.message ? err.message : String(err),
    plain: plainFor(code, err && err.message),
    fix: fixFor(code),
    where: (err && err.where) || context || 'page',
    /* The engine's structured context, when it sent any. Without it the panel
       can only print the sentence; with it, it can name the condition. */
    node: (err && err.node) || '',
    field: (err && err.field) || '',
    operator: (err && err.operator) || '',
    condition: (err && err.condition) || '',
    alternatives: (err && err.alternatives) || [],
  };
}

export function addProblem(problem) {
  const existing = state.ui.problems.findIndex(
    (p) => p.code === problem.code && p.message === problem.message,
  );
  if (existing >= 0) {
    state.ui.problems[existing] = problem;
  } else {
    state.ui.problems.push(problem);
  }
  /* A problem is not an edit: it must not mark the rule unsaved. */
  rerender();
}

/** Remove ONE problem, not every problem sharing its code.
 *
 *  Two refusals with the same code are two different failures — a different
 *  field, a different operator. Dismissing by code alone cleared the one the
 *  analyst was not looking at. */
export function dismissProblem(target) {
  const code = target && target.code ? target.code : target;
  const message = target && target.message;
  state.ui.problems = state.ui.problems.filter(
    (p) => p.code !== code || (message !== undefined && p.message !== message),
  );
  rerender();
}

export function clearProblems() {
  state.ui.problems = [];
}

let notifier = () => {};
export function setNotifier(fn) {
  notifier = fn;
}

/** Run an async action; every failure becomes a visible Problem plus a toast.
    Screens use this so no rejection is ever silently dropped. */
export async function attempt(fn, options) {
  const opts = options || {};
  try {
    return await fn();
  } catch (err) {
    if (err && err.handled) return null;
    const problem = problemFromError(err, opts.context);
    if (err) err.handled = true;
    state.ui.problems = state.ui.problems
      .filter((p) => !(p.code === problem.code && p.message === problem.message));
    state.ui.problems.push(problem);
    notifier(problem);
    rerender();
    return null;
  }
}

/** Jump to the control that fixes a problem, and focus it. */
export function applyFix(fix) {
  if (!fix) return;
  if (fix.href) {
    window.location.hash = fix.href;
    if (fix.focus) {
      /* The screen mounts on the next frame; focus after it exists. */
      requestAnimationFrame(() => {
        const node = document.querySelector(fix.focus);
        if (node) {
          node.focus();
          node.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }
      });
    }
  }
}
