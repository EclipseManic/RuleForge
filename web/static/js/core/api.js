/* The HTTP surface: one function per endpoint, one error shape.

   Nothing here interprets a response. The engine's refusals carry a code, a
   message written for an analyst and a `where`; they are passed through
   unchanged so the Problems panel can show the engine's own words next to the
   plain sentence from `problems.js`. */

import { state } from './state.js';

export class ApiError extends Error {
  /* `node`, `field`, `operator`, `condition` and `alternatives` come from the
     engine's structured refusal. They are carried through unchanged so the
     Problems panel can point at the condition that failed and offer the
     spelling that would have worked. */
  constructor(code, message, where, severity, details) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.where = where;
    this.severity = severity || 'error';
    const extra = details || {};
    this.node = extra.node || '';
    this.field = extra.field || '';
    this.operator = extra.operator || '';
    this.condition = extra.condition || '';
    this.alternatives = extra.alternatives || [];
  }
}

async function request(method, path, body) {
  const started = performance.now();
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (err) {
    state.ui.lastRequest = { method, path, at: new Date().toISOString() };
    state.ui.lastResponse = { transport: 'failed', detail: String(err) };
    throw new ApiError(
      'NETWORK',
      'cannot reach the workbench at ' + location.origin +
        '. The server may have stopped.',
      'network',
    );
  }

  const text = await response.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (err) {
      data = { raw: text.slice(0, 400) };
    }
  }

  state.ui.lastRequest = {
    method,
    path,
    body: body === undefined ? null : body,
    status: response.status,
    ms: Math.round(performance.now() - started),
    at: new Date().toISOString(),
  };
  state.ui.lastResponse = data;

  if (!response.ok) {
    const error = data.error || {};
    throw new ApiError(
      error.code || 'SERVER_ERROR',
      error.message || ('the server answered ' + response.status + ' with no explanation.'),
      error.where || 'api',
      error.severity || (response.status >= 500 ? 'error' : 'error'),
      error,
    );
  }
  return data;
}

const get = (path) => request('GET', path, undefined);
const post = (path, body) => request('POST', path, body);
const del = (path) => request('DELETE', path, undefined);

/* -- reads ---------------------------------------------------------------- */

export const health = () => get('/api/health');
export const dialects = () => get('/api/dialects');
export const vocabulary = () => get('/api/vocabulary');

export function history(params) {
  const query = new URLSearchParams();
  if (params && params.q) query.set('q', params.q);
  if (params && params.origin) query.set('origin', params.origin);
  if (params && params.dialect) query.set('dialect', params.dialect);
  if (params && params.limit) query.set('limit', params.limit);
  return get('/api/history?' + query.toString());
}

export const entry = (id) => get('/api/history/' + encodeURIComponent(id));
export const lineage = (id) => get('/api/history/' + encodeURIComponent(id) + '/lineage');
export const forgetEntry = (id) => del('/api/history/' + encodeURIComponent(id));

export function datasets(q) {
  const query = new URLSearchParams();
  if (q) query.set('q', q);
  return get('/api/datasets?' + query.toString());
}

export const dataset = (id) => get('/api/datasets/' + encodeURIComponent(id));
export const testRuns = () => get('/api/test-runs');
export const testRun = (id) => get('/api/test-runs/' + encodeURIComponent(id));

/* -- rule work ------------------------------------------------------------ */

export const lower = (dialect, text, ruleId) =>
  post('/api/lower', { dialect, text, rule_id: ruleId || 'rule' });

export const render = (dialect, payload) =>
  post('/api/render', { dialect, rule: payload });

export const validate = (payload) => post('/api/validate', { rule: payload });
export const outline = (payload) => post('/api/outline', { rule: payload });

export const evaluate = (payload, text, format) =>
  post('/api/evaluate', { rule: payload, text, format });

export const synthesize = (text, format, options) =>
  post('/api/synthesize', { text, format, options });

/* -- writes --------------------------------------------------------------- */

export const saveVersion = (payload, fields) =>
  post('/api/history', {
    rule: payload,
    origin: fields.origin || 'authored',
    source_text: fields.sourceText || '',
    parent_id: fields.parentId ?? null,
    note: fields.note || '',
  });

export const saveDataset = (fields) =>
  post('/api/datasets', {
    name: fields.name,
    description: fields.description || '',
    format: fields.format || 'jsonl',
    table: fields.table || 'events',
    labels: fields.labels || [],
    text: fields.text,
  });

export const saveRun = (fields) =>
  post('/api/test-runs', {
    rule: fields.payload,
    dataset_id: fields.datasetId,
    expected_verdict: fields.expectedVerdict || '',
    purpose: fields.purpose || 'manual',
    note: fields.note || '',
    rule_entry_id: fields.ruleEntryId ?? null,
  });
