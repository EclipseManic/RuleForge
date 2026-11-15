/* RuleForge GUI.

   The builder edits the IR DIRECTLY -- the same tagged JSON the codec reads and
   writes. There is deliberately no second, simplified rule model in the
   browser, because a parallel representation is exactly how a tool ends up
   showing one thing in the form and rendering another in the rule.

   So `state.rule` here is a codec payload, and every edit mutates it in place.
   The tags (`{"@": "str", "v": ...}`) are verbose to read but they are the
   reason a Decimal threshold survives the trip and ABSENT stays distinct from
   null and "".
*/

'use strict';

/* ---------------------------------------------------------------- codec */

const T = {
  str:  v => ({'@': 'str', v: String(v)}),
  int:  v => ({'@': 'int', v: Math.trunc(v)}),
  bool: v => ({'@': 'bool', v: !!v}),
  dec:  v => ({'@': 'decimal', v: String(v)}),
  nul:  () => ({'@': 'null'}),
  absent: () => ({'@': 'absent'}),
  tuple: items => ({'@': 'tuple', v: items}),
  list:  items => ({'@': 'list', v: items}),
  dict:  pairs => ({'@': 'dict', v: pairs}),
  cap:  v => ({'@': 'capability', v: v || 'evaluated'}),
};

/** A JS value out of a tagged node, for display and for form fields. */
function plain(node) {
  if (node === null || node === undefined) return null;
  const tag = node['@'];
  if (tag === 'absent') return '<absent>';
  if (tag === 'undecided') return '<undecided>';
  if (tag === 'null') return null;
  if (tag === 'tuple' || tag === 'list') return node.v.map(plain);
  if (tag === 'dict') {
    const out = {};
    for (const [k, v] of node.v) out[plain(k)] = plain(v);
    return out;
  }
  return node.v;
}

/** Guess a literal's tag from what the analyst typed.

    Numbers become decimals, not floats: this engine is Decimal end to end, and
    a threshold that becomes 10.499999 in transit is a different control. */
function literalFromText(text) {
  const raw = String(text);
  const trimmed = raw.trim();
  if (trimmed === '') return T.str('');
  if (trimmed === 'null') return T.nul();
  if (trimmed === 'true') return T.bool(true);
  if (trimmed === 'false') return T.bool(false);
  if (/^-?\d+$/.test(trimmed)) return T.dec(trimmed);
  if (/^-?\d*\.\d+$/.test(trimmed)) return T.dec(trimmed);
  return T.str(raw);
}

function literalToText(node) {
  if (!node) return '';
  const tag = node['@'];
  if (tag === 'null') return 'null';
  if (tag === 'absent') return '';
  if (tag === 'bool') return node.v ? 'true' : 'false';
  return String(node.v);
}

const COMPARISON_OPS = [
  '==', '!=', '<', '<=', '>', '>=', 'contains', 'in', 'contains_any',
  'contains_all', 'startswith', 'endswith', 'matches', 'like', 'ilike',
  '=~', '!~',
];

/* Kept in step with what `pipeline.py::_measure` actually computes.
   `percentile`, `stdev`, `arg_max` and `arg_min` were missing here while the
   engine had just gained them, so a measure the backend supports could not be
   chosen in the builder at all. */
const MEASURE_FUNCTIONS = [
  'count', 'count_if', 'dcount', 'sum', 'min', 'max', 'avg', 'stdev',
  'percentile', 'arg_max', 'arg_min', 'earliest', 'latest',
  'make_set', 'make_list',
];

/* ------------------------------------------------------------ IR builders */

function node(kind, fields) {
  return Object.assign({'@': kind, id: T.str(fields.id || ''),
                        capability: T.cap(), note: T.str('')}, fields);
}

function fieldRef(name, scope) {
  const parts = String(name || '').split('.').filter(p => p !== '');
  const head = parts.length ? parts[0] : 'field';
  return {
    '@': 'FieldRef',
    name: T.str(head),
    path: T.tuple(parts.slice(1).map(T.str)),
    scope: T.str(scope || 'current'),
  };
}

function fieldRefText(ref) {
  if (!ref || ref['@'] !== 'FieldRef') return '';
  const path = (ref.path && ref.path.v ? ref.path.v : []).map(p => p.v);
  return [ref.name.v].concat(path).join('.');
}

function comparison(op, left, right) {
  return {'@': 'Comparison', op: T.str(op), left: left, right: right,
          negate: T.bool(false)};
}

function literal(value) { return {'@': 'Literal', value: value}; }

function newComparison() {
  return comparison('==', fieldRef('FieldName'), literal(T.str('')));
}

function boolOp(op, operands) {
  return {'@': 'BoolOp', op: T.str(op), operands: T.tuple(operands)};
}

function emptyRule() {
  return {
    schema: 1,
    rule: {
      '@': 'Rule',
      rule_id: T.str('new-rule'),
      pipeline: T.tuple([
        node('Read', {id: T.str('source'), table: T.str('SecurityEvent'),
                      selector: T.str(''), time_field: T.str('')}),
        node('Filter', {id: T.str('where_1'), condition: newComparison()}),
        node('Emit', {id: T.str('out'), keeps: T.tuple([]),
                      dedupe_by: T.tuple([])}),
      ]),
      bindings: T.tuple([]),
      annotations: {
        '@': 'Annotations',
        title: T.str(''), description: T.str(''), severity: T.str(''),
        author: T.str(''), mitre_attack: T.tuple([]),
        references: T.tuple([]), false_positives: T.tuple([]),
      },
      metadata: T.dict([]),
      output: T.str(''),
    },
  };
}

/** A fresh stage of `kind`, valid at construction.

    The IR refuses half-built nodes -- an empty BoolOp is the always-true
    predicate, an Aggregate with no measure discards every value -- so the
    defaults here are real values rather than blanks. */
function newStage(kind, index) {
  const id = kind.toLowerCase() + '_' + index;
  switch (kind) {
    case 'Filter':
      return node('Filter', {id: T.str(id), condition: newComparison()});
    case 'Aggregate':
      return node('Aggregate', {
        id: T.str(id),
        measures: T.tuple([{'@': 'Measure', function: T.str('count'),
                            name: T.str('Hits'), field: T.nul(),
                            distinct: T.bool(false), param: T.nul()}]),
        keys: T.tuple([fieldRef('Computer')]),
        window: T.nul(),
      });
    case 'Derive':
      return node('Derive', {
        id: T.str(id),
        assignments: T.tuple([T.tuple([T.str('NewColumn'),
                                       literal(T.str(''))])]),
        kind: T.str('add'),
      });
    case 'Project':
      return node('Project', {id: T.str(id), renames: T.tuple([]),
                              drops: T.tuple([]),
                              keeps: T.tuple([fieldRef('Computer')])});
    case 'Sort':
      return node('Sort', {
        id: T.str(id),
        keys: T.tuple([T.tuple([fieldRef('Computer'), T.bool(true)])]),
        limit: T.nul(),
      });
    case 'Limit':
      return node('Limit', {id: T.str(id), count: T.int(100),
                            keep_last: T.bool(false)});
    case 'Distinct':
      return node('Distinct', {id: T.str(id),
                               keys: T.tuple([fieldRef('Computer')])});
    case 'Expand':
      return node('Expand', {id: T.str(id), field: fieldRef('Values'),
                             into: T.str('')});
    case 'Correlation':
      return node('Correlation', {
        id: T.str(id), parent: T.str('source'), frequency: T.int(5),
        timeframe: {'@': 'Duration', seconds: T.dec('300')},
        group_by: T.tuple([fieldRef('Computer')]),
        count_subject: T.str('parent'),
      });
    /* Two steps and a join key, because `ir.Sequence` refuses anything less:
       one step is an ordinary filter, and a sequence with nothing to join on
       pairs any first event with any later one anywhere in the estate. */
    case 'Sequence':
      return node('Sequence', {
        id: T.str(id),
        steps: T.tuple([
          {'@': 'SequenceStep', condition: newComparison(), runs: T.int(1)},
          {'@': 'SequenceStep', condition: newComparison(), runs: T.int(1)},
        ]),
        by: T.tuple([fieldRef('Computer')]),
        maxspan: {'@': 'Duration', seconds: T.dec('300')},
        until: T.nul(),
      });
    default:
      throw new Error(kind + ' is not a stage this builder creates');
  }
}

/* ------------------------------------------------------------------ state */

const state = {
  rule: emptyRule(),
  dialect: 'sentinel',
  dialects: [],
  parentId: null,
  origin: 'authored',
  sourceText: '',
  selectedEntry: null,
  datasets: [],
  selectedDatasetId: null,
  testRuns: [],
  selectedTestRunId: null,
  /* Which studio section the Studio tab returns to. The rail kept all
     seven panes flat and visible at once; the header shows two levels
     instead, so the second level has to remember where you were. */
  studioPane: 'build',
};

const $ = sel => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  /* Dynamic stage controls are rebuilt from the IR, so they cannot be wrapped
     in the static <label> elements used elsewhere in the template. Give every
     generated form control a usable fallback name; specific controls below
     replace it with a more precise label where that context is available. */
  if (tag === 'input' || tag === 'select' || tag === 'textarea') {
    const fallback = cls === 'f-name' ? 'field name'
      : cls === 'f-value' ? 'value'
      : cls === 'f-scope' ? 'field scope'
      : cls === 'f-op' ? 'operator'
      : tag + ' control';
    n.setAttribute('aria-label', fallback);
  }
  if (text !== undefined) n.textContent = text;
  return n;
};

function toast(message, kind, code) {
  const box = $('#toast');
  box.className = 'toast' + (kind ? ' ' + kind : '');
  box.textContent = '';
  if (code) box.appendChild(el('code', null, code));
  box.appendChild(document.createTextNode(message));
  box.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { box.hidden = true; }, kind === 'bad' ? 12000 : 5000);
}

/** Every call goes through here, so a refusal is surfaced the same way
    everywhere: with its code and the engine's own reason. The engine writes
    messages for the analyst, so showing them verbatim is the right thing. */
async function call(method, path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: method,
      headers: body === undefined ? {} : {'Content-Type': 'application/json'},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (err) {
    toast('cannot reach the workbench. Is `python -m ruleforge` still running?',
          'bad');
    throw err;
  }
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; }
  catch (err) {
    toast('the workbench returned something that is not JSON.', 'bad');
    throw err;
  }
  if (!response.ok) {
    const error = data.error || {};
    toast(error.message || ('request failed with ' + response.status),
          'bad', error.code);
    const err = new Error(error.message || 'request failed');
    err.code = error.code;
    err.handled = true;
    throw err;
  }
  return data;
}

/* ------------------------------------------------- condition editor */

/** Render a condition subtree into `host`.

    `replace` is how a node swaps itself for a different one: a comparison that
    becomes an AND of two comparisons calls `replace(boolOp(...))`. Passing the
    setter down means no node needs to know its own address in the tree. */
function renderCondition(host, expr, replace) {
  host.textContent = '';
  if (!expr) {
    const add = el('button', 'mini', '+ condition');
    add.onclick = () => { replace(newComparison()); };
    host.appendChild(add);
    return;
  }

  const kind = expr['@'];

  if (kind === 'BoolOp') {
    const wrap = el('div', 'cond');
    const head = el('div', 'cond-row');
    const label = el('span', 'cond-op-label', expr.op.v.toUpperCase());
    label.title = 'click to switch between AND and OR';
    label.style.cursor = 'pointer';
    label.onclick = () => {
      expr.op = T.str(expr.op.v === 'and' ? 'or' : 'and');
      renderCondition(host, expr, replace);
    };
    head.appendChild(label);

    const add = el('button', 'mini', '+');
    add.title = 'add another operand';
    add.onclick = () => {
      expr.operands.v.push(newComparison());
      renderCondition(host, expr, replace);
    };
    head.appendChild(add);

    const unwrap = el('button', 'icon', 'ungroup');
    unwrap.onclick = () => {
      // An empty BoolOp is the always-true predicate, which in a filter
      // matches every row -- so ungrouping collapses to the first operand
      // rather than leaving an empty group behind.
      replace(expr.operands.v.length ? expr.operands.v[0] : newComparison());
    };
    head.appendChild(unwrap);
    wrap.appendChild(head);

    expr.operands.v.forEach((operand, i) => {
      const slot = el('div');
      renderCondition(slot, operand, next => {
        if (next === null) {
          expr.operands.v.splice(i, 1);
          if (expr.operands.v.length === 0) { replace(newComparison()); return; }
          if (expr.operands.v.length === 1) { replace(expr.operands.v[0]); return; }
        } else {
          expr.operands.v[i] = next;
        }
        renderCondition(host, expr, replace);
      });
      wrap.appendChild(slot);
    });
    host.appendChild(wrap);
    return;
  }

  if (kind === 'Not') {
    const wrap = el('div', 'cond');
    const head = el('div', 'cond-row');
    head.appendChild(el('span', 'cond-neg', 'NOT'));
    const strip = el('button', 'icon', 'remove not');
    strip.onclick = () => { replace(expr.operand); };
    head.appendChild(strip);
    wrap.appendChild(head);
    const slot = el('div');
    renderCondition(slot, expr.operand, next => {
      if (next === null) { replace(null); return; }
      expr.operand = next;
      renderCondition(host, expr, replace);
    });
    wrap.appendChild(slot);
    host.appendChild(wrap);
    return;
  }

  if (kind === 'Comparison') {
    const row = el('div', 'cond-row');

    const scope = el('select', 'f-scope');
    scope.setAttribute('aria-label', 'Condition field scope');
    ['current', 'left', 'right'].forEach(s => {
      const option = el('option', null, s);
      option.value = s;
      if (expr.left['@'] === 'FieldRef' && expr.left.scope.v === s) {
        option.selected = true;
      }
      scope.appendChild(option);
    });
    scope.title = 'which row this field is read from. left and right are the ' +
                  'two sides of a join and mean nothing outside one.';
    scope.onchange = () => {
      expr.left = fieldRef(fieldRefText(expr.left), scope.value);
    };
    row.appendChild(scope);

    const name = el('input', 'f-name');
    name.type = 'text';
    name.setAttribute('aria-label', 'Condition field name');
    name.value = fieldRefText(expr.left);
    name.placeholder = 'win.eventdata.Image';
    name.onchange = () => {
      expr.left = fieldRef(name.value, scope.value);
    };
    row.appendChild(name);

    const op = el('select', 'f-op');
    op.setAttribute('aria-label', 'Condition operator');
    COMPARISON_OPS.forEach(o => {
      const option = el('option', null, o);
      option.value = o;
      if (expr.op.v === o) option.selected = true;
      op.appendChild(option);
    });
    op.onchange = () => { expr.op = T.str(op.value); };
    row.appendChild(op);

    const value = el('input', 'f-value');
    value.type = 'text';
    value.setAttribute('aria-label', 'Condition comparison value');
    value.placeholder = 'value';
    /* A REGEX right-hand side is shown as its pattern, and edited back into a
       Regex -- keeping its flavour and its case-insensitivity.

       It used to show an empty box: `literalToText` only understood a
       `Literal`, so a condition like `ObjectName endswith "lsass.exe"` --
       which this dialect folds into a case-folding regex -- appeared as the
       operator `matches` with NO value. The analyst could not see the
       pattern, and typing in that box replaced the Regex with a plain string,
       silently turning a case-insensitive suffix test into a case-sensitive
       exact match. The rendered pane showed the truth while the editor showed
       something else, which is the one thing this builder is supposed never
       to do. */
    const isRegex = expr.right['@'] === 'Regex';
    value.value = isRegex
      ? expr.right.pattern.v
      : (expr.right['@'] === 'Literal' ? literalToText(expr.right.value) : '');
    value.title = isRegex
      ? 'a ' + expr.right.dialect.v + ' pattern'
        + (expr.right.nocase.v ? ', matched without regard to case' : '')
      : 'numbers are sent as exact decimals, never as floats';
    value.onchange = () => {
      if (isRegex) {
        /* Rebuilt as a Regex, so the dialect and the nocase flag survive an
           edit. Replacing it with a Literal would change what the rule means
           without saying so. */
        expr.right = {
          '@': 'Regex',
          pattern: T.str(value.value),
          dialect: expr.right.dialect,
          nocase: expr.right.nocase,
        };
      } else {
        expr.right = literal(literalFromText(value.value));
      }
    };
    row.appendChild(value);

    if (isRegex) {
      /* The flavour and the case rule are stated, because a pattern that
         matches regardless of case reads identically to one that does not. */
      const tag = el('span', 'badge',
        expr.right.nocase.v ? 'regex · any case' : 'regex');
      tag.title = expr.right.dialect.v
        + (expr.right.nocase.v
            ? ' — this pattern ignores upper and lower case'
            : ' — this pattern is case-sensitive');
      row.appendChild(tag);
    }

    const negate = el('button', 'icon', expr.negate.v ? 'NOT' : 'not');
    negate.title = 'negate this comparison';
    if (expr.negate.v) negate.style.color = 'var(--bad)';
    negate.onclick = () => {
      expr.negate = T.bool(!expr.negate.v);
      renderCondition(host, expr, replace);
    };
    row.appendChild(negate);

    const group = el('button', 'icon', 'AND');
    group.title = 'group this with another condition';
    group.onclick = () => { replace(boolOp('and', [expr, newComparison()])); };
    row.appendChild(group);

    const drop = el('button', 'icon', '\u00d7');
    drop.title = 'remove';
    drop.onclick = () => { replace(null); };
    row.appendChild(drop);

    host.appendChild(row);
    return;
  }

  /* Anything the editor cannot draw is shown as read-only text rather than
     silently dropped. A pasted rule can contain a Span, a SubQuery or a
     Call, and discarding it on load would hand back a different rule than
     the one the analyst imported. */
  const row = el('div', 'cond-row');
  const shown = el('span', 'ol-expr', describeExpr(expr));
  row.appendChild(shown);
  const tag = el('span', 'badge', kind);
  tag.title = 'this node is kept exactly as imported; the form cannot edit ' +
              'it yet, so it is shown rather than dropped';
  row.appendChild(tag);
  const drop = el('button', 'icon', '\u00d7');
  drop.onclick = () => { replace(null); };
  row.appendChild(drop);
  host.appendChild(row);
}

/** Readable text for a node the form cannot draw. Display only. */
function describeExpr(expr) {
  if (!expr) return '';
  const kind = expr['@'];
  if (kind === 'FieldRef') {
    const scope = expr.scope.v;
    return (scope === 'current' ? '' : scope + '.') + fieldRefText(expr);
  }
  if (kind === 'Literal') return JSON.stringify(plain(expr.value));
  if (kind === 'Comparison') {
    const body = describeExpr(expr.left) + ' ' + expr.op.v + ' ' +
                 describeExpr(expr.right);
    return expr.negate.v ? 'NOT (' + body + ')' : body;
  }
  if (kind === 'BoolOp') {
    return '(' + expr.operands.v.map(describeExpr)
      .join(' ' + expr.op.v.toUpperCase() + ' ') + ')';
  }
  if (kind === 'Not') return 'NOT ' + describeExpr(expr.operand);
  if (kind === 'Arith') {
    return '(' + describeExpr(expr.left) + ' ' + expr.op.v + ' ' +
           describeExpr(expr.right) + ')';
  }
  if (kind === 'Span') {
    return describeExpr(expr.value) + ' between (' + describeExpr(expr.low) +
           ' .. ' + describeExpr(expr.high) + ')';
  }
  if (kind === 'ListExpr') {
    return '[' + expr.items.v.map(describeExpr).join(', ') + ']';
  }
  if (kind === 'Regex') {
    return '/' + expr.pattern.v + '/' + expr.dialect.v +
           (expr.nocase.v ? ' nocase' : '');
  }
  if (kind === 'Call') {
    return expr.function.v + '(' +
           expr.args.v.map(describeExpr).join(', ') + ')';
  }
  if (kind === 'SubQuery') {
    return '[ ' + expr.pipeline.v.length + ' stages ]';
  }
  if (kind === 'Duration') return expr.seconds.v + 's';
  return kind;
}

/* ------------------------------------------------------- stage rendering */

function renderStages() {
  const host = $('#stages');
  host.textContent = '';
  const stages = state.rule.rule.pipeline.v;

  stages.forEach((stage, index) => {
    const kind = stage['@'];
    if (kind === 'Read') return;  /* edited in the left column */

    const card = el('div', 'stage' + (kind === 'Emit' ? ' terminal' : ''));
    const head = el('div', 'stage-head');
    head.appendChild(el('span', 'stage-kind', kind));
    head.appendChild(el('span', 'stage-id', stage.id.v));
    if (stage.capability && stage.capability.v === 'declared_only') {
      const badge = el('span', 'badge declared', 'appliance only');
      badge.title = 'modelled and rendered correctly, but only the vendor ' +
                    'engine can run it';
      head.appendChild(badge);
    }
    head.appendChild(el('span', 'spacer'));

    if (kind !== 'Emit') {
      const up = el('button', 'icon', '\u2191');
      up.onclick = () => { moveStage(index, -1); };
      head.appendChild(up);
      const down = el('button', 'icon', '\u2193');
      down.onclick = () => { moveStage(index, 1); };
      head.appendChild(down);
      const drop = el('button', 'icon', '\u00d7');
      drop.onclick = () => {
        stages.splice(index, 1);
        renderStages();
      };
      head.appendChild(drop);
    }
    card.appendChild(head);

    const body = el('div', 'stage-body');
    renderStageBody(body, stage);
    card.appendChild(body);
    host.appendChild(card);
  });
}

function moveStage(index, delta) {
  const stages = state.rule.rule.pipeline.v;
  const target = index + delta;
  /* Read stays first and Emit stays last: the source is not a stage you can
     reorder past, and a rule whose output is not at the end returns whatever
     happened to follow it. */
  if (target < 1 || target >= stages.length - 1) return;
  const moved = stages.splice(index, 1)[0];
  stages.splice(target, 0, moved);
  renderStages();
}

function fieldListEditor(host, label, tupleNode, scoped) {
  const wrap = el('div');
  wrap.appendChild(el('div', 'hint', label));
  tupleNode.v.forEach((ref, i) => {
    const row = el('div', 'cond-row');
    const input = el('input', 'f-name');
    input.type = 'text';
    input.value = fieldRefText(ref);
    input.onchange = () => {
      tupleNode.v[i] = fieldRef(input.value, scoped ? ref.scope.v : 'current');
    };
    row.appendChild(input);
    const drop = el('button', 'icon', '\u00d7');
    drop.onclick = () => { tupleNode.v.splice(i, 1); redrawStageBody(host); };
    row.appendChild(drop);
    wrap.appendChild(row);
  });
  const add = el('button', 'mini', '+ field');
  add.onclick = () => {
    tupleNode.v.push(fieldRef('FieldName'));
    redrawStageBody(host);
  };
  wrap.appendChild(add);
  host.appendChild(wrap);
}

function redrawStageBody(host) {
  const stage = host._stage;
  renderStageBody(host, stage);
}

function renderStageBody(host, stage) {
  host.textContent = '';
  host._stage = stage;
  const kind = stage['@'];

  if (kind === 'Filter') {
    const slot = el('div');
    renderCondition(slot, stage.condition, next => {
      // A filter whose condition is a bare field matches almost everything,
      // because any non-empty string is truthy. The engine refuses that, so
      // removing the last condition restores a real comparison rather than
      // leaving the stage empty.
      stage.condition = next || newComparison();
      renderStageBody(host, stage);
    });
    host.appendChild(slot);
    return;
  }

  if (kind === 'Aggregate') {
    stage.measures.v.forEach((measure, i) => {
      const row = el('div', 'cond-row');
      const fn = el('select');
      MEASURE_FUNCTIONS.forEach(f => {
        const option = el('option', null, f);
        option.value = f;
        if (measure.function.v === f) option.selected = true;
        fn.appendChild(option);
      });
      fn.onchange = () => { measure.function = T.str(fn.value); };
      row.appendChild(fn);

      const field = el('input', 'f-name');
      field.type = 'text';
      field.placeholder = 'field (blank for count)';
      field.value = measure.field && measure.field['@'] === 'FieldRef'
        ? fieldRefText(measure.field) : '';
      field.onchange = () => {
        measure.field = field.value.trim()
          ? fieldRef(field.value) : T.nul();
      };
      row.appendChild(field);

      const as = el('input', 'f-value');
      as.type = 'text';
      as.placeholder = 'output name';
      as.value = measure.name.v;
      as.onchange = () => { measure.name = T.str(as.value); };
      row.appendChild(as);

      const distinct = el('button', 'icon', measure.distinct.v ? 'distinct' : 'all');
      distinct.title = 'values() de-duplicates and make_set() does not, and ' +
                       'that difference changes an alert';
      distinct.onclick = () => {
        measure.distinct = T.bool(!measure.distinct.v);
        renderStageBody(host, stage);
      };
      row.appendChild(distinct);

      const drop = el('button', 'icon', '\u00d7');
      drop.onclick = () => {
        // An Aggregate with no measure produces one row per group and
        // discards every value, which the engine refuses.
        if (stage.measures.v.length === 1) {
          toast('a group-by with nothing measured discards every value. ' +
                'Use a Distinct stage if that is what you want.', 'bad');
          return;
        }
        stage.measures.v.splice(i, 1);
        renderStageBody(host, stage);
      };
      row.appendChild(drop);
      host.appendChild(row);
    });

    const add = el('button', 'mini', '+ measure');
    add.onclick = () => {
      stage.measures.v.push({'@': 'Measure', function: T.str('count'),
                             name: T.str('n' + stage.measures.v.length),
                             field: T.nul(), distinct: T.bool(false),
                             param: T.nul()});
      renderStageBody(host, stage);
    };
    host.appendChild(add);
    fieldListEditor(host, 'group by', stage.keys, false);

    /* window */
    const hasWindow = stage.window && stage.window['@'] === 'Window';
    const toggle = el('button', 'mini', hasWindow ? 'remove window' : '+ time window');
    toggle.onclick = () => {
      stage.window = hasWindow ? T.nul() : {
        '@': 'Window', kind: T.str('tumbling'),
        size: {'@': 'Duration', seconds: T.dec('300')},
        step: T.nul(), time_field: T.str(''), gap: T.nul(),
      };
      renderStageBody(host, stage);
    };
    host.appendChild(toggle);

    if (hasWindow) {
      const row = el('div', 'cond-row');
      const kindSelect = el('select');
      ['tumbling', 'sliding', 'cumulative', 'per_event', 'session'].forEach(k => {
        const option = el('option', null, k);
        option.value = k;
        if (stage.window.kind.v === k) option.selected = true;
        kindSelect.appendChild(option);
      });
      kindSelect.onchange = () => {
        const next = kindSelect.value;
        stage.window.kind = T.str(next);
        /* A sliding window needs a step and a tumbling one must not carry
           it; a session window is defined by its gap. The engine refuses a
           parameter it would ignore, so the form clears them on switch. */
        stage.window.step = next === 'sliding'
          ? {'@': 'Duration', seconds: T.dec('60')} : T.nul();
        stage.window.gap = next === 'session'
          ? {'@': 'Duration', seconds: T.dec('900')} : T.nul();
        if (next === 'sliding' && stage.window.size['@'] === 'null') {
          stage.window.size = {'@': 'Duration', seconds: T.dec('300')};
        }
        renderStageBody(host, stage);
      };
      row.appendChild(kindSelect);

      const sizeInput = el('input', 'f-value');
      sizeInput.type = 'text';
      sizeInput.placeholder = 'size in seconds';
      sizeInput.value = stage.window.size['@'] === 'Duration'
        ? stage.window.size.seconds.v : '';
      sizeInput.onchange = () => {
        stage.window.size = sizeInput.value.trim()
          ? {'@': 'Duration', seconds: T.dec(sizeInput.value.trim())} : T.nul();
      };
      row.appendChild(sizeInput);

      if (stage.window.kind.v === 'sliding') {
        const stepInput = el('input', 'f-value');
        stepInput.type = 'text';
        stepInput.placeholder = 'step in seconds';
        stepInput.value = stage.window.step['@'] === 'Duration'
          ? stage.window.step.seconds.v : '';
        stepInput.onchange = () => {
          stage.window.step = {'@': 'Duration', seconds: T.dec(stepInput.value.trim() || '60')};
        };
        row.appendChild(stepInput);
      }
      if (stage.window.kind.v === 'session') {
        const gapInput = el('input', 'f-value');
        gapInput.type = 'text';
        gapInput.placeholder = 'gap in seconds';
        gapInput.value = stage.window.gap['@'] === 'Duration'
          ? stage.window.gap.seconds.v : '';
        gapInput.onchange = () => {
          stage.window.gap = {'@': 'Duration', seconds: T.dec(gapInput.value.trim() || '900')};
        };
        row.appendChild(gapInput);
      }
      host.appendChild(row);
    }
    return;
  }

  if (kind === 'Derive') {
    stage.assignments.v.forEach((pair, i) => {
      const row = el('div', 'cond-row');
      const target = el('input', 'f-name');
      target.type = 'text';
      target.value = pair.v[0].v;
      target.onchange = () => { pair.v[0] = T.str(target.value); };
      row.appendChild(target);
      row.appendChild(el('span', null, '='));
      const value = el('input', 'f-value');
      value.type = 'text';
      value.value = pair.v[1]['@'] === 'Literal'
        ? literalToText(pair.v[1].value) : describeExpr(pair.v[1]);
      value.onchange = () => {
        pair.v[1] = literal(literalFromText(value.value));
      };
      row.appendChild(value);
      const drop = el('button', 'icon', '\u00d7');
      drop.onclick = () => {
        if (stage.assignments.v.length === 1) {
          toast('a derive stage that computes nothing is refused.', 'bad');
          return;
        }
        stage.assignments.v.splice(i, 1);
        renderStageBody(host, stage);
      };
      row.appendChild(drop);
      host.appendChild(row);
    });
    const add = el('button', 'mini', '+ column');
    add.onclick = () => {
      stage.assignments.v.push(T.tuple([T.str('NewColumn'), literal(T.str(''))]));
      renderStageBody(host, stage);
    };
    host.appendChild(add);
    return;
  }

  if (kind === 'Project') {
    /* keeps and drops are mutually exclusive in the IR: a stage that does
       both is ambiguous about what the output is, and guessing produces a
       projection that keeps a column the author removed. */
    const mode = el('div', 'cond-row');
    const keeping = stage.drops.v.length === 0;
    const toggle = el('button', 'mini', keeping ? 'keeping columns' : 'dropping columns');
    toggle.onclick = () => {
      if (keeping) {
        stage.drops = T.tuple(stage.keeps.v.slice());
        stage.keeps = T.tuple([]);
        stage.renames = T.tuple([]);
      } else {
        stage.keeps = T.tuple(stage.drops.v.slice());
        stage.drops = T.tuple([]);
      }
      renderStageBody(host, stage);
    };
    mode.appendChild(toggle);
    host.appendChild(mode);

    if (keeping) {
      fieldListEditor(host, 'keep these columns', stage.keeps, false);
      stage.renames.v.forEach((pair, i) => {
        const row = el('div', 'cond-row');
        const from = el('input', 'f-name');
        from.type = 'text';
        from.value = fieldRefText(pair.v[0]);
        from.onchange = () => { pair.v[0] = fieldRef(from.value); };
        row.appendChild(from);
        row.appendChild(el('span', null, '\u2192'));
        const to = el('input', 'f-name');
        to.type = 'text';
        to.value = pair.v[1].v;
        to.onchange = () => { pair.v[1] = T.str(to.value); };
        row.appendChild(to);
        const drop = el('button', 'icon', '\u00d7');
        drop.onclick = () => {
          stage.renames.v.splice(i, 1);
          renderStageBody(host, stage);
        };
        row.appendChild(drop);
        host.appendChild(row);
      });
      const addRename = el('button', 'mini', '+ rename');
      addRename.onclick = () => {
        stage.renames.v.push(T.tuple([fieldRef('Source'), T.str('Target')]));
        renderStageBody(host, stage);
      };
      host.appendChild(addRename);
    } else {
      fieldListEditor(host, 'drop these columns', stage.drops, false);
    }
    return;
  }

  if (kind === 'Sort') {
    stage.keys.v.forEach((pair, i) => {
      const row = el('div', 'cond-row');
      const field = el('input', 'f-name');
      field.type = 'text';
      field.value = fieldRefText(pair.v[0]);
      field.onchange = () => { pair.v[0] = fieldRef(field.value); };
      row.appendChild(field);
      const dir = el('button', 'mini', pair.v[1].v ? 'descending' : 'ascending');
      dir.onclick = () => {
        pair.v[1] = T.bool(!pair.v[1].v);
        renderStageBody(host, stage);
      };
      row.appendChild(dir);
      const drop = el('button', 'icon', '\u00d7');
      drop.onclick = () => { stage.keys.v.splice(i, 1); renderStageBody(host, stage); };
      row.appendChild(drop);
      host.appendChild(row);
    });
    const add = el('button', 'mini', '+ sort key');
    add.onclick = () => {
      stage.keys.v.push(T.tuple([fieldRef('FieldName'), T.bool(true)]));
      renderStageBody(host, stage);
    };
    host.appendChild(add);
    return;
  }

  if (kind === 'Limit') {
    const row = el('div', 'cond-row');
    const count = el('input', 'f-value');
    count.type = 'text';
    count.value = String(stage.count.v);
    count.onchange = () => {
      const parsed = parseInt(count.value, 10);
      stage.count = T.int(isNaN(parsed) ? 100 : parsed);
    };
    row.appendChild(count);
    const last = el('button', 'mini', stage.keep_last.v ? 'last rows' : 'first rows');
    last.onclick = () => {
      stage.keep_last = T.bool(!stage.keep_last.v);
      renderStageBody(host, stage);
    };
    row.appendChild(last);
    host.appendChild(row);
    return;
  }

  if (kind === 'Distinct') {
    fieldListEditor(host, 'distinct on', stage.keys, false);
    return;
  }

  if (kind === 'Expand') {
    const row = el('div', 'cond-row');
    const field = el('input', 'f-name');
    field.type = 'text';
    field.value = fieldRefText(stage.field);
    field.onchange = () => { stage.field = fieldRef(field.value); };
    row.appendChild(field);
    row.appendChild(el('span', null, '\u2192'));
    const into = el('input', 'f-name');
    into.type = 'text';
    into.placeholder = 'into (optional)';
    into.value = stage.into.v;
    into.onchange = () => { stage.into = T.str(into.value); };
    row.appendChild(into);
    host.appendChild(row);
    return;
  }

  if (kind === 'Correlation') {
    const row = el('div', 'cond-row');
    const parent = el('input', 'f-name');
    parent.type = 'text';
    parent.placeholder = 'parent stage or binding';
    parent.value = stage.parent.v;
    parent.onchange = () => { stage.parent = T.str(parent.value); };
    row.appendChild(parent);
    const freq = el('input', 'f-value');
    freq.type = 'text';
    freq.placeholder = 'times';
    freq.value = String(stage.frequency.v);
    freq.onchange = () => {
      const parsed = parseInt(freq.value, 10);
      stage.frequency = T.int(isNaN(parsed) || parsed < 1 ? 1 : parsed);
    };
    row.appendChild(freq);
    const within = el('input', 'f-value');
    within.type = 'text';
    within.placeholder = 'within seconds';
    within.value = stage.timeframe.seconds.v;
    within.onchange = () => {
      stage.timeframe = {'@': 'Duration',
                         seconds: T.dec(within.value.trim() || '300')};
    };
    row.appendChild(within);
    host.appendChild(row);
    host.appendChild(el('div', 'hint',
      'The count is the predicate: the rule fires when the parent matches ' +
      'this many times inside the timeframe, per group.'));
    fieldListEditor(host, 'grouped on', stage.group_by, false);
    return;
  }

  if (kind === 'Sequence') {
    /* The ORDER is the whole point of this stage -- `procdump` then `lsass`
       is credential dumping and the reverse is not -- so the steps are
       NUMBERED and cannot be reordered by accident. This editor was missing
       entirely, so an EQL sequence loaded into the builder and then fell
       through to a read-only text blob: the one rule type that most needs
       tuning was the one rule type that could not be tuned. */
    const head = el('div', 'cond-row');
    const within = el('input', 'f-value');
    within.type = 'text';
    within.placeholder = 'within seconds (blank for unbounded)';
    within.value = stage.maxspan['@'] === 'Duration'
      ? stage.maxspan.seconds.v : '';
    within.onchange = () => {
      const text = within.value.trim();
      /* Unbounded is a real choice and a dangerous one: the steps may then be
         a year apart and still fire. It is allowed and stated, not silently
         defaulted. */
      stage.maxspan = text
        ? {'@': 'Duration', seconds: T.dec(text)}
        : T.nul();
    };
    head.appendChild(within);
    host.appendChild(head);
    host.appendChild(el('div', 'hint',
      'The window is measured from the FIRST step to the last, not between ' +
      'consecutive steps.'));

    fieldListEditor(host, 'the steps must agree on', stage.by, false);

    stage.steps.v.forEach((step, i) => {
      const box = el('div', 'ol-stage');
      const label = el('div');
      label.appendChild(el('span', 'ol-kind', 'step ' + (i + 1)));
      const runs = el('input', 'f-value');
      runs.type = 'text';
      runs.placeholder = 'repeats';
      runs.value = String(step.runs.v);
      runs.onchange = () => {
        const parsed = parseInt(runs.value, 10);
        /* `ir.SequenceStep` refuses runs < 1: a step that matches no events
           is one the sequence can never advance past. */
        step.runs = T.int(isNaN(parsed) || parsed < 1 ? 1 : parsed);
        runs.value = String(step.runs.v);
      };
      label.appendChild(runs);
      if (stage.steps.v.length > 2) {
        const drop = el('button', 'mini', 'remove');
        drop.onclick = () => {
          stage.steps.v.splice(i, 1);
          renderStageBody(host, stage);
        };
        label.appendChild(drop);
      }
      box.appendChild(label);
      const slot = el('div');
      renderCondition(slot, step.condition, next => { step.condition = next; });
      box.appendChild(slot);
      host.appendChild(box);
    });

    const add = el('button', 'mini', 'add a step');
    add.onclick = () => {
      stage.steps.v.push({'@': 'SequenceStep', condition: newComparison(),
                          runs: T.int(1)});
      renderStageBody(host, stage);
    };
    host.appendChild(add);

    const cancelRow = el('div');
    const hasUntil = stage.until && stage.until['@'] !== 'null';
    const toggle = el('button', 'mini',
      hasUntil ? 'remove the cancellation' : 'add a cancellation');
    toggle.onclick = () => {
      /* `until` abandons a partial sequence. A chain that was cancelled --
         the user logged off, the process exited -- is not a detection, and
         completing it anyway reports an attack that did not happen. */
      stage.until = hasUntil ? T.nul() : newComparison();
      renderStageBody(host, stage);
    };
    cancelRow.appendChild(toggle);
    host.appendChild(cancelRow);
    if (hasUntil) {
      host.appendChild(el('div', 'hint',
        'When this matches, any partial sequence for the key is abandoned.'));
      const slot = el('div');
      renderCondition(slot, stage.until, next => { stage.until = next; });
      host.appendChild(slot);
    }
    return;
  }

  if (kind === 'Emit') {
    fieldListEditor(host, 'columns to output (blank for all)', stage.keeps, false);
    fieldListEditor(host, 'de-duplicate alerts on', stage.dedupe_by, false);
    return;
  }

  /* No editor for this kind. Stated rather than shown as an empty panel: a
     stage that silently renders nothing looks like a stage with no settings,
     and the analyst edits around it believing they have seen all of it. */
  host.appendChild(el('div', 'ol-expr', describeExpr(stage)));
  host.appendChild(el('div', 'msg caution',
    'This builder has no editor for a ' + kind + ' stage yet, so it is shown '
    + 'read-only. It is preserved exactly as it was imported.'));
}

/* ------------------------------------------------------ metadata binding */

function readRule() {
  const rule = state.rule.rule;
  rule.rule_id = T.str($('#rule-id').value.trim() || 'rule');

  const an = rule.annotations;
  an.title = T.str($('#an-title').value);
  an.description = T.str($('#an-description').value);
  an.severity = T.str($('#an-severity').value);
  an.author = T.str($('#an-author').value);
  an.references = T.tuple(linesOf($('#an-references').value).map(T.str));
  an.false_positives = T.tuple(linesOf($('#an-fps').value).map(T.str));
  an.mitre_attack = T.tuple(linesOf($('#an-mitre').value).map(line => {
    const colon = line.indexOf(':');
    const tactic = colon < 0 ? line.trim() : line.slice(0, colon).trim();
    const techniques = colon < 0 ? [] :
      line.slice(colon + 1).split(',').map(t => t.trim()).filter(Boolean);
    return T.tuple([T.str(tactic), T.tuple(techniques.map(T.str))]);
  }));

  const read = rule.pipeline.v.find(s => s['@'] === 'Read');
  if (read) {
    read.table = T.str($('#read-table').value.trim() || 'events');
    read.selector = T.str($('#read-selector').value);
    read.time_field = T.str($('#read-timefield').value);
  }

  /* The dialect a rule BELONGS to is its provenance -- what it was lowered
     from. `state.dialect` is the target the dropdown renders INTO. They are
     different things, and this function used to replace the entire metadata
     dict with the second one.

     That reclassified an imported Wazuh rule as Sentinel the moment the form
     was read, and took every `wazuh.*` key with it: `render_wazuh` then had no
     `wazuh.if_sid` and fell back to `level="4"` and `<group>local</group>`,
     so a Wazuh rule did not survive its own round trip through the builder.
     It also defeated the cross-dialect audit, which compares provenance
     against the target -- overwritten, the two always matched and nothing was
     ever reported.

     Provenance is preserved. Only the keys this form owns are written, and
     `dialect`/`language` are filled in solely when the rule arrived without
     them. */
  const meta = new Map(((rule.metadata && rule.metadata.v) || [])
    .map(pair => [pair[0].v, pair[1]]));
  if (!meta.has('dialect')) {
    meta.set('dialect', T.str(state.dialect));
    meta.set('language', T.str(languageOf(state.dialect)));
  }
  if (!meta.has('artifact')) meta.set('artifact', T.str('rule'));
  rule.metadata = T.dict(
    Array.from(meta, ([key, value]) => [T.str(key), value]));
  return state.rule;
}

function writeForm() {
  const rule = state.rule.rule;
  $('#rule-id').value = rule.rule_id.v;
  const an = rule.annotations;
  $('#an-title').value = an.title.v;
  $('#an-description').value = an.description.v;
  $('#an-severity').value = an.severity.v;
  $('#an-author').value = an.author.v;
  $('#an-references').value = an.references.v.map(r => r.v).join('\n');
  $('#an-fps').value = an.false_positives.v.map(r => r.v).join('\n');
  $('#an-mitre').value = an.mitre_attack.v.map(pair => {
    const tactic = pair.v[0].v;
    const techniques = pair.v[1].v.map(t => t.v).join(', ');
    return techniques ? tactic + ': ' + techniques : tactic;
  }).join('\n');

  const read = rule.pipeline.v.find(s => s['@'] === 'Read');
  $('#read-table').value = read ? read.table.v : '';
  $('#read-selector').value = read ? read.selector.v : '';
  $('#read-timefield').value = read ? read.time_field.v : '';

  renderStages();
}

const linesOf = text => String(text).split('\n').map(l => l.trim()).filter(Boolean);
const languageOf = key => {
  const found = state.dialects.find(d => d.key === key);
  return found ? found.language : '';
};

/* ----------------------------------------------------------- diagnostics */

function renderMessages(host, messages) {
  host.textContent = '';
  if (!messages || !messages.length) {
    host.appendChild(el('div', 'empty', 'Nothing to report.'));
    return;
  }
  messages.forEach(message => {
    const box = el('div', 'msg ' + (message.severity || 'note'));
    box.appendChild(el('code', null, message.code));
    box.appendChild(document.createTextNode(message.message));
    if (message.where) {
      box.appendChild(el('div', 'where', message.where));
    }
    /* `verified` separates "I checked this against the text" from "this is a
       reading of the rule". A caveat that looks measured but is not is worse
       than no caveat. */
    if (message.verified === false) {
      box.appendChild(el('div', 'unverified',
        'inferred from the rule, not measured against your sample'));
    }
    host.appendChild(box);
  });
}

function renderOutline(host, outline) {
  host.textContent = '';
  if (!outline) { host.appendChild(el('div', 'empty', '\u2014')); return; }

  const an = outline.annotations || {};
  if (an.title) host.appendChild(el('div', 'ol-kind', an.title));
  if (an.description) host.appendChild(el('div', 'hint', an.description));
  const facts = [];
  if (an.severity) facts.push('severity ' + an.severity);
  if (an.author) facts.push('by ' + an.author);
  if (outline.language) facts.push(outline.language);
  if (facts.length) host.appendChild(el('div', 'hint', facts.join(' \u00b7 ')));
  (an.mitre_attack || []).forEach(entry => {
    host.appendChild(el('div', 'ol-expr',
      entry.tactic + ': ' + (entry.techniques || []).join(', ')));
  });

  (outline.bindings || []).forEach(binding => {
    const box = el('div', 'ol-binding');
    box.appendChild(el('h3', null, 'binding ' + binding.name));
    if (binding.guard) {
      box.appendChild(el('div', 'ol-expr', 'guard: ' + binding.guard));
    }
    binding.stages.forEach(stage => box.appendChild(outlineStage(stage)));
    host.appendChild(box);
  });

  host.appendChild(el('h3', null, 'pipeline'));
  (outline.pipeline || []).forEach(stage => host.appendChild(outlineStage(stage)));
}

function outlineStage(stage) {
  const box = el('div', 'ol-stage');
  const head = el('div');
  head.appendChild(el('span', 'ol-kind', stage.kind));
  if (stage.id) head.appendChild(el('span', 'stage-id', ' ' + stage.id));
  if (stage.capability === 'declared_only') {
    head.appendChild(el('span', 'badge declared', 'appliance only'));
  }
  box.appendChild(head);
  if (stage.condition) box.appendChild(el('div', 'ol-expr', stage.condition));
  if (stage.predicate) box.appendChild(el('div', 'ol-expr', stage.predicate));

  /* A Sequence keeps its conditions on its STEPS, so the two lines above find
     nothing and the most complex stage in the model rendered as a bare word.
     The ORDER is the entire point of the node -- `procdump` then `lsass` is
     credential dumping and the reverse is not -- so the steps are numbered
     rather than listed, and the window and join key are shown next to them
     because a sequence without either means something much broader. */
  if (stage.ordered && stage.steps) {
    const facts = [];
    if (stage.by && stage.by.length) facts.push('joined on ' + stage.by.join(', '));
    if (stage.maxspan) facts.push('within ' + stage.maxspan);
    if (facts.length) box.appendChild(el('div', 'hint', facts.join(' \u00b7 ')));
    stage.steps.forEach(step => {
      const line = el('div', 'ol-expr');
      line.appendChild(el('span', 'stage-id', step.position + '. '));
      line.appendChild(document.createTextNode(step.condition));
      if (step.runs > 1) {
        line.appendChild(el('span', 'badge declared', step.runs + '\u00d7'));
      }
      box.appendChild(line);
    });
    if (stage.until) {
      box.appendChild(el('div', 'ol-expr',
        'cancelled by: ' + stage.until));
    }
  }

  if (stage.note) box.appendChild(el('div', 'hint', stage.note));
  return box;
}

/* ------------------------------------------------------------ evaluation */

function renderEvaluation(host, result) {
  host.textContent = '';

  const verdict = el('div', 'verdict ' + result.verdict);
  const text = {
    matched: 'Matched',
    no_match: 'No match',
    not_evaluated: 'Not evaluated',
  }[result.verdict] || result.verdict;
  verdict.appendChild(el('span', null, text));
  if (result.verdict === 'not_evaluated') {
    verdict.appendChild(el('span', 'hint',
      'This is not "no match". Something in the rule could not be decided ' +
      'from these events, so a confident no would be a guess.'));
  }
  host.appendChild(verdict);

  if (result.refusal) {
    const box = el('div', 'msg problem');
    box.appendChild(el('code', null, result.refusal.code));
    box.appendChild(document.createTextNode(result.refusal.message));
    host.appendChild(box);
  }

  if (result.rows && result.rows.length) {
    const columns = [];
    result.rows.forEach(row => {
      Object.keys(row).forEach(key => {
        if (columns.indexOf(key) < 0) columns.push(key);
      });
    });
    const table = el('table', 'grid');
    const head = el('tr');
    columns.forEach(c => head.appendChild(el('th', null, c)));
    table.appendChild(head);
    result.rows.slice(0, 200).forEach(row => {
      const tr = el('tr');
      columns.forEach(c => {
        const td = el('td');
        td.appendChild(renderValue(row[c]));
        tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    host.appendChild(el('h2', null, 'Output rows (' + result.rows.length + ')'));
    host.appendChild(table);
  }

  if (result.trace && result.trace.length) {
    host.appendChild(el('h2', null, 'Per-stage row ledger'));
    const table = el('table', 'grid');
    const head = el('tr');
    ['stage', 'kind', 'in', 'out', 'dropped', 'undecided'].forEach(c => {
      head.appendChild(el('th', null, c));
    });
    table.appendChild(head);
    result.trace.forEach(t => {
      const tr = el('tr');
      tr.appendChild(el('td', null, t.stage));
      tr.appendChild(el('td', null, t.kind));
      tr.appendChild(el('td', 'num', String(t.rows_in)));
      tr.appendChild(el('td', 'num', String(t.rows_out)));
      tr.appendChild(el('td', 'num', String(t.dropped)));
      const und = el('td', 'num', String(t.undecided));
      if (t.undecided > 0) und.classList.add('tag-undecided');
      tr.appendChild(und);
      table.appendChild(tr);
    });
    host.appendChild(table);
    host.appendChild(el('div', 'hint',
      'Read this top to bottom to find the stage that dropped the rows you ' +
      'expected to keep.'));
  }

  host.appendChild(el('h2', null, 'Why'));
  renderMessages(host.appendChild(el('div')), result.caveats);
}

function renderValue(value) {
  if (value === null || value === undefined) {
    return el('span', 'tag-null', 'null');
  }
  if (typeof value === 'object' && value.$ === 'absent') {
    const span = el('span', 'tag-absent', 'absent');
    span.title = 'the field is not in the row at all, which is not the same ' +
                 'as null or an empty string';
    return span;
  }
  if (typeof value === 'object' && value.$ === 'undecided') {
    const span = el('span', 'tag-undecided', 'undecided');
    span.title = 'this could not be decided from the data given';
    return span;
  }
  if (typeof value === 'object' && value.$ === 'seq') {
    return el('span', null, '[' + value.items.map(i => {
      const inner = renderValue(i);
      return inner.textContent;
    }).join(', ') + ']');
  }
  if (typeof value === 'object' && value.$ === 'duration') {
    return el('span', null, value.seconds + 's');
  }
  if (typeof value === 'object') {
    return el('span', null, JSON.stringify(value));
  }
  return el('span', null, String(value));
}

/* ------------------------------------------------------------------ wiring */

/* The left rail that listed all seven panes flat is gone. Navigation is two
   levels in the header now, which is the shape Event Analyzer and Phishing
   Mail Detector already use: Home explains the tool, Studio is where the work
   happens, and the six working sections sit under Studio.

   A pane name still selects a screen, so every existing caller -- the four
   landing cards, the load paths, the brand -- keeps working unchanged. */
function selectTab(name) {
  const main = name === 'home' ? 'home' : 'studio';
  if (main === 'studio') state.studioPane = name;

  document.querySelectorAll('#tabs .tab').forEach(t => {
    t.classList.toggle('active', t.dataset.main === main);
  });
  document.querySelectorAll('#subtabs .tab').forEach(t => {
    t.classList.toggle('active', t.dataset.pane === name);
  });
  /* The second level only means anything while the Studio is open. */
  const subtabs = $('#subtabs');
  if (subtabs) subtabs.hidden = main !== 'studio';

  document.querySelectorAll('.pane').forEach(p => {
    p.classList.toggle('active', p.id === 'pane-' + name);
  });
  const labels = {
    home: 'Home', build: 'Workbench', import: 'Import & Explain',
    fromlog: 'From Log', datasets: 'Datasets', testruns: 'Test Runs',
    history: 'History',
  };
  const context = $('#current-context');
  if (context) context.textContent = labels[name] || name;
  if (name === 'history') loadHistory();
  if (name === 'datasets') loadDatasets();
  if (name === 'testruns') {
    loadDatasets();
    loadTestRuns();
  }
}

async function loadDialects() {
  const data = await call('GET', '/api/dialects');
  state.dialects = data.dialects;

  const fill = (select, includePlanned) => {
    select.textContent = '';
    data.dialects.forEach(d => {
      if (!includePlanned && d.status !== 'ready') return;
      const option = el('option', null,
        d.label + ' (' + d.language + ')' +
        (d.status === 'ready' ? '' : ' \u2014 planned'));
      option.value = d.key;
      option.disabled = d.status !== 'ready';
      if (d.note) option.title = d.note;
      select.appendChild(option);
    });
  };

  fill($('#dialect'), true);
  fill($('#import-dialect'), true);

  const historyDialect = $('#history-dialect');
  historyDialect.textContent = '';
  const any = el('option', null, 'any dialect');
  any.value = '';
  historyDialect.appendChild(any);
  data.dialects.forEach(d => {
    const option = el('option', null, d.label);
    option.value = d.key;
    historyDialect.appendChild(option);
  });

  const ready = data.dialects.find(d => d.status === 'ready');
  if (ready) {
    state.dialect = ready.key;
    $('#dialect').value = ready.key;
    $('#import-dialect').value = ready.key;
  }

  const planned = data.dialects.filter(d => d.status !== 'ready').length;
  if (planned) {
    toast(data.dialects.length - planned + ' of ' + data.dialects.length +
          ' dialects are implemented. The rest are listed so you can see ' +
          'what is coming rather than wondering why they are missing.', 'good');
  }

  /* The landing page names them rather than claiming "eight dialects" in
     prose, so the page cannot go stale when one is added or renamed. */
  const listing = $('#home-dialects');
  if (listing) {
    listing.textContent = '';
    data.dialects.filter(d => d.status === 'ready').forEach(d => {
      listing.appendChild(el('div', null, d.label + ' \u00b7 ' + d.language));
    });
  }
}

/* --------------------------------------------------------- evidence library */

function formatTime(value) {
  return String(value || '').replace('T', ' ').replace('+00:00', 'Z');
}

function datasetOptions(select, datasets) {
  if (!select) return;
  const current = state.selectedDatasetId || select.value;
  select.textContent = '';
  const empty = el('option', null, 'Select a local dataset');
  empty.value = '';
  select.appendChild(empty);
  datasets.forEach(dataset => {
    const option = el('option', null,
      dataset.name + ' · ' + dataset.event_count + ' events');
    option.value = String(dataset.id);
    option.title = dataset.content_hash;
    select.appendChild(option);
  });
  if (current && datasets.some(dataset => String(dataset.id) === String(current))) {
    select.value = String(current);
  }
}

function renderDatasetList(datasets) {
  const host = $('#dataset-list');
  if (!host) return;
  host.textContent = '';
  if (!datasets.length) {
    host.appendChild(el('div', 'empty',
      'No datasets yet. Add a representative event fixture to begin replay.'));
    return;
  }
  datasets.forEach(dataset => {
    const row = el('div', 'dataset-row' +
      (state.selectedDatasetId === dataset.id ? ' selected' : ''));
    const head = el('div', 'dataset-row-head');
    head.appendChild(el('span', 'dataset-row-title', dataset.name));
    head.appendChild(el('span', 'status-chip success', 'local'));
    row.appendChild(head);
    row.appendChild(el('div', 'dataset-row-meta',
      dataset.event_count + ' events · ' + dataset.format + ' · ' +
      (dataset.table || 'events')));
    if (dataset.labels && dataset.labels.length) {
      row.appendChild(el('div', 'hint', dataset.labels.join(' · ')));
    }
    row.onclick = () => openDataset(dataset.id);
    host.appendChild(row);
  });
}

async function loadDatasets() {
  const query = $('#dataset-q') ? $('#dataset-q').value.trim() : '';
  const params = new URLSearchParams();
  if (query) params.set('q', query);
  try {
    const data = await call('GET', '/api/datasets?' + params.toString());
    state.datasets = data.datasets || [];
    const count = $('#dataset-count');
    if (count) count.textContent = String(data.total || 0);
    renderDatasetList(state.datasets);
    datasetOptions($('#build-dataset'), state.datasets);
    datasetOptions($('#test-run-dataset'), state.datasets);
  } catch (err) {
    if (!err.handled) throw err;
  }
}

async function openDataset(datasetId) {
  try {
    const data = await call('GET', '/api/datasets/' + datasetId);
    state.selectedDatasetId = data.id;
    datasetOptions($('#build-dataset'), state.datasets);
    datasetOptions($('#test-run-dataset'), state.datasets);
    ['#build-dataset', '#test-run-dataset'].forEach(selector => {
      const select = $(selector);
      if (select) select.value = String(data.id);
    });
    renderDatasetList(state.datasets);
    const host = $('#dataset-preview');
    if (host) {
      host.className = 'dataset-preview';
      host.textContent = '';
      host.appendChild(el('div', 'eyebrow', 'NORMALIZED PREVIEW'));
      host.appendChild(el('div', 'hint', data.name + ' · hash ' +
        String(data.content_hash).slice(0, 16) + '…'));
      const pre = el('pre');
      pre.textContent = JSON.stringify(data.events || [], null, 2);
      host.appendChild(pre);
      if (data.warnings && data.warnings.length) {
        const warnings = el('div');
        renderMessages(warnings, data.warnings.map(message => ({
          code: 'DATASET_WARNING', message, severity: 'caution',
        })));
        host.appendChild(warnings);
      }
    }
  } catch (err) {
    if (!err.handled) throw err;
  }
}

async function doDatasetSave() {
  const name = $('#dataset-name').value.trim();
  const text = $('#dataset-text').value.trim();
  if (!name) { toast('give the dataset a name first.', 'bad'); return; }
  if (!text) { toast('paste at least one event into the dataset.', 'bad'); return; }
  try {
    const data = await call('POST', '/api/datasets', {
      name,
      description: $('#dataset-description').value,
      format: $('#dataset-format').value,
      table: $('#dataset-table').value.trim() || 'events',
      labels: linesOf($('#dataset-labels').value.replace(/,/g, '\n')),
      text,
    });
    state.selectedDatasetId = data.id;
    $('#dataset-text').value = '';
    await loadDatasets();
    await openDataset(data.id);
    toast('Dataset ' + data.id + ' saved with ' + data.event_count +
      ' event(s). It is now available for replay.', 'good');
  } catch (err) {
    if (!err.handled) throw err;
  }
}

function verdictChip(verdict) {
  if (verdict === 'matched') return ['success', 'matched'];
  if (verdict === 'not_evaluated') return ['uncertain', 'not evaluated'];
  if (verdict === 'refused') return ['danger', 'refused'];
  return ['warning', 'no match'];
}

function renderTestRunList(runs) {
  const host = $('#test-run-list');
  if (!host) return;
  host.textContent = '';
  if (!runs.length) {
    host.appendChild(el('div', 'empty',
      'No saved runs yet. Evidence appears here after the first replay.'));
    return;
  }
  runs.forEach(run => {
    const row = el('div', 'testrun-row' +
      (state.selectedTestRunId === run.id ? ' selected' : ''));
    const head = el('div', 'testrun-row-head');
    const chip = verdictChip(run.actual_verdict);
    head.appendChild(el('span', 'status-chip ' + chip[0], chip[1]));
    head.appendChild(el('span', 'testrun-row-title',
      run.title || run.rule_id || 'Untitled rule'));
    row.appendChild(head);
    row.appendChild(el('div', 'testrun-row-meta',
      '#' + run.id + ' · dataset ' + run.dataset_id + ' · ' +
      formatTime(run.created_at)));
    if (run.matches_expected !== null) {
      row.appendChild(el('div', 'hint', run.matches_expected
        ? 'Expected verdict matched.' : 'Expected verdict did not match.'));
    }
    row.onclick = () => openTestRun(run.id);
    host.appendChild(row);
  });
}

async function loadTestRuns() {
  try {
    const data = await call('GET', '/api/test-runs');
    state.testRuns = data.test_runs || [];
    const count = $('#test-run-count');
    if (count) count.textContent = String(data.total || 0);
    renderTestRunList(state.testRuns);
  } catch (err) {
    if (!err.handled) throw err;
  }
}

async function openTestRun(runId) {
  try {
    const data = await call('GET', '/api/test-runs/' + runId);
    state.selectedTestRunId = data.id;
    renderTestRunList(state.testRuns);
    const host = $('#test-run-result');
    if (host) {
      host.className = '';
      host.textContent = '';
      renderEvaluation(host, data.result);
      const summary = el('div', 'evidence-summary');
      summary.appendChild(el('span', 'status-chip ' + verdictChip(data.actual_verdict)[0],
        verdictChip(data.actual_verdict)[1]));
      summary.appendChild(el('span', 'hint',
        'rule ' + data.rule_hash.slice(0, 16) + '… · dataset ' +
        data.dataset_hash.slice(0, 16) + '…'));
      host.insertBefore(summary, host.firstChild);
    }
  } catch (err) {
    if (!err.handled) throw err;
  }
}

/* ------------------------------------------------------------ the start pane

   A WORKED EXAMPLE rather than more label text. Reading a filled-in rule
   teaches the shape of one faster than any amount of prose, and the Build tab
   opened empty: eleven blank metadata fields, a placeholder condition, and an
   output box reading em-dash. There was nothing to learn from and nothing to
   change.

   Written as KQL and lowered by the server rather than hand-built as IR, so
   the example cannot drift out of step with what the parser actually accepts
   -- an example that no longer loads is worse than none. */
const EXAMPLE_DIALECT = 'sentinel';
const EXAMPLE_RULE = [
  '// title: LSASS access from an unsigned process',
  '// description: Credential theft via direct memory access to LSASS.',
  '// severity: high',
  '// author: example',
  '// attack: credential-access: T1003.001',
  '',
  'SecurityEvent',
  '| where EventID == 4656',
  '| where ObjectName endswith "lsass.exe"',
  '| where AccessMask == "0x1410"',
].join('\n');

const EXAMPLE_SAMPLE = [
  '{"EventID": 4656, "ObjectName": "C:\\\\Windows\\\\System32\\\\lsass.exe",',
  ' "AccessMask": "0x1410", "Computer": "WS-01",',
  ' "TimeGenerated": 1767182400}',
].join('');

async function loadExample() {
  try {
    const data = await call('POST', '/api/lower',
      {dialect: EXAMPLE_DIALECT, text: EXAMPLE_RULE});
    state.rule = data.rule;
    state.origin = 'authored';
    state.sourceText = EXAMPLE_RULE;
    state.parentId = null;
    state.dialect = EXAMPLE_DIALECT;
    $('#dialect').value = EXAMPLE_DIALECT;
    writeForm();
    /* The sample is filled in too, so Run does something the first time it is
       pressed. An example that renders but cannot be tested only teaches half
       of what the tool does. */
    $('#events').value = EXAMPLE_SAMPLE;
    selectTab('build');
    await doRender();
    toast('An example rule is loaded. Change the Dialect at the top right to '
          + 'watch it rewrite itself, or press Run to test it against the '
          + 'sample.', 'good');
  } catch (err) {
    if (!err.handled) throw err;
  }
}

function startBlank() {
  state.rule = emptyRule();
  state.origin = 'authored';
  state.sourceText = '';
  state.parentId = null;
  writeForm();
  selectTab('build');
  markStale();
}


/* The rendered pane must never show text that is not the rule in front of
   you. It did: editing a value from 4624 to 9999 left the old text on screen,
   and switching the dialect from Sentinel to Splunk left KQL on screen while
   the dropdown read Splunk -- so the LABEL contradicted the content. An
   analyst copies that into their SIEM and deploys the old threshold, or the
   wrong language entirely.

   Two mechanisms, because either alone has a hole. `markStale` fires the
   instant anything changes, so there is no window where the pane looks
   authoritative and is not. The debounced re-render then replaces it, so the
   analyst does not have to remember to press a button to see the truth. */
let renderTimer = null;
let renderedFor = null;

function markStale() {
  const pane = $('#rendered');
  if (pane) {
    const already = pane.classList.contains('stale');
    pane.classList.add('stale');
    if (!already && pane.textContent.trim()
        && pane.textContent.trim() !== '\u2014') {
      /* Said in words as well as greyed out. Colour alone is not a message,
         and the person most likely to copy stale text is the one not looking
         at it closely. */
      const note = el('div', 'stale-note',
        'This is the PREVIOUS render \u2014 the rule has changed since.');
      pane.insertBefore(note, pane.firstChild);
    }
  }
  /* The VERDICT is invalidated too, and this was the worse half of the bug.
     Changing `EventID == 4624` to `9999` re-rendered the query correctly and
     left "Matched" on screen -- the answer for the old rule. So the two panes
     contradicted each other, and the fresh one made the stale verdict look
     trustworthy: a rule that cannot match was reporting a successful match
     against a sample. That is a false confirmation, which is the one output
     this tool exists not to produce.

     Not re-run automatically: running costs a round trip over a sample that
     may be large, and the analyst asked for it once. It is cleared and
     labelled instead, so the only way to see a verdict is to ask for one
     about the rule as it now stands. */
  const verdict = $('#evaluation');
  if (verdict && verdict.innerHTML.trim()
      && !verdict.classList.contains('stale')) {
    verdict.classList.add('stale');
    const note = el('div', 'stale-note',
      'The rule has changed \u2014 this verdict is about the PREVIOUS '
      + 'version. Press Run again.');
    verdict.insertBefore(note, verdict.firstChild);
  }
}

function scheduleRender() {
  markStale();
  if (renderTimer) clearTimeout(renderTimer);
  /* Debounced rather than per-keystroke: a render is a round trip, and
     rendering on every character would make typing a field name fire a dozen
     requests and show a dozen refusals for half-typed input. */
  renderTimer = setTimeout(() => { renderTimer = null; doRender(); }, 450);
}

async function doRender() {
  const body = readRule();
  const want = state.dialect;
  try {
    const data = await call('POST', '/api/render',
      {dialect: want, rule: body});
    if (want !== state.dialect) {
      /* The dialect changed while this request was in flight. Showing the
         answer to the old question under the new label is the exact lie this
         pane was fixed to stop telling. */
      return;
    }
    const pane = $('#rendered');
    pane.classList.remove('stale');
    pane.textContent = data.text;
    renderedFor = want;
    /* The language is named next to the text, so the content and the dropdown
       cannot disagree without it being visible. */
    const label = $('#rendered-for');
    if (label) label.textContent = languageOf(want) || want;
    /* These were hardcoded to [] -- the pane said "Nothing to report" while
       the server was reporting that a narrowing clause had been dropped. The
       whole point of returning them is that the analyst sees them next to the
       text they qualify. */
    const notes = data.diagnostics || [];
    renderMessages($('#diagnostics'), notes);
    /* A dropped source selector makes the rendered rule BROADER than the one
       it came from. That is not a footnote, and the diagnostics pane can sit
       below the fold, so it also gets said out loud. */
    const widened = notes.filter(n => n.severity === 'problem').length;
    if (widened) {
      toast(widened + ' clause(s) could not be carried into ' +
            (languageOf(want) || want) + '. This rendered ' +
            'rule matches MORE than the original \u2014 read the notes before ' +
            'deploying it.', 'bad');
    }
  } catch (err) {
    if (!err.handled) throw err;
    /* Cleared, not left stale. A refusal means there IS no valid output for
       this rule, and leaving the last good text on screen under a refusal
       message is how the wrong rule gets copied. */
    const pane = $('#rendered');
    pane.classList.remove('stale');
    pane.textContent = '\u2014';
    renderedFor = null;
    const label = $('#rendered-for');
    if (label) label.textContent = '';
  }
}

async function doValidate() {
  try {
    const data = await call('POST', '/api/validate', {rule: readRule()});
    toast('This rule is structurally sound and no pattern in it would hang ' +
          'the engine that runs it.', 'good');
    renderMessages($('#diagnostics'), []);
    renderOutline($('#import-outline'), data.outline);
  } catch (err) {
    if (!err.handled) throw err;
  }
}

async function doRun() {
  const raw = $('#events').value.trim();
  if (!raw) { toast('paste at least one event to test against.', 'bad'); return; }
  /* The sample is sent as TEXT and parsed on the server. This used to parse
     here, with `parseLogs` and `coerce` -- which disagreed with the Python
     parser the From Log tab uses: JavaScript left `1.5` a string and `-` a
     string where Python produced a decimal and a null. The same pasted line
     meant different things in two tabs, and only one of the two parsers could
     be reached by a test. One parser now, and it is the tested one -- which
     also gives this box `kv` and `syslog` support it never had. */
  try {
    const result = await call('POST', '/api/evaluate', {
      rule: readRule(),
      text: raw,
      format: $('#events-format') ? $('#events-format').value
            : (raw.startsWith('[') ? 'json' : 'jsonl'),
    });
    /* The stale flag is cleared only on a SUCCESSFUL run, so a verdict on
       screen always belongs to the rule on screen. */
    $('#evaluation').classList.remove('stale');
    renderEvaluation($('#evaluation'), result);
  } catch (err) {
    if (!err.handled) throw err;
    /* Cleared rather than left behind a refusal. A verdict under an error
       message is a verdict somebody will read. */
    $('#evaluation').classList.remove('stale');
    $('#evaluation').textContent = '';
  }
}

async function saveEvidence(targetSelector) {
  const target = $(targetSelector);
  const select = targetSelector === '#evaluation'
    ? $('#build-dataset') : $('#test-run-dataset');
  const datasetId = select ? Number(select.value) : 0;
  if (!datasetId) {
    toast('select a saved dataset before saving evidence.', 'bad');
    return;
  }
  try {
    const data = await call('POST', '/api/test-runs', {
      rule: readRule(),
      dataset_id: datasetId,
      expected_verdict: targetSelector === '#evaluation'
        ? $('#build-expected').value : $('#test-run-expected').value,
      purpose: targetSelector === '#evaluation'
        ? 'manual' : $('#test-run-purpose').value,
      note: targetSelector === '#evaluation'
        ? '' : $('#test-run-note').value,
      rule_entry_id: state.parentId,
    });
    state.selectedTestRunId = data.id;
    if (target) {
      target.classList.remove('stale');
      target.classList.remove('empty');
      renderEvaluation(target, data.result);
    }
    await loadTestRuns();
    toast('Evidence run ' + data.id + ' saved. The rule and dataset hashes are ' +
      'now linked in history.', data.matches_expected === false ? 'bad' : 'good');
  } catch (err) {
    if (!err.handled) throw err;
  }
}

async function doTestRunSave() {
  await saveEvidence('#test-run-result');
}

async function doImport() {
  const text = $('#import-text').value;
  const dialect = $('#import-dialect').value;
  if (!text.trim()) { toast('paste a rule first.', 'bad'); return; }
  try {
    const data = await call('POST', '/api/lower',
      {dialect: dialect, text: text});
    state.rule = data.rule;
    state.dialect = dialect;
    state.origin = 'imported';
    state.sourceText = text;
    state.parentId = null;
    $('#dialect').value = dialect;
    writeForm();
    renderOutline($('#import-outline'), data.outline);
    renderMessages($('#import-diagnostics'), data.diagnostics);
    const lost = data.diagnostics.length;
    toast('Loaded into the builder.' + (lost
      ? ' ' + lost + ' thing(s) could not be represented \u2014 they are ' +
        'listed rather than dropped.'
      : ' Everything in it was representable.'), 'good');
    selectTab('build');
    doRender();
  } catch (err) {
    if (!err.handled) throw err;
  }
}

async function doFromLog() {
  /* The analysis used to run HERE, in the browser: field stability, the
     volatility heuristics and the rule assembly were all JavaScript, which
     made the most consequential decision in the tool -- which fields become
     the detection -- the one decision the Python test suite could not reach.
     It is now `ruleforge/synthesize.py` behind `/api/synthesize`, so there is
     one implementation and it is tested. This function only collects the
     options and renders what comes back. */
  const options = {
    table: $('#log-table').value.trim(),
    skip_volatile: $('#opt-skip-volatile').checked,
    skip_timestamps: $('#opt-skip-timestamps').checked,
    threshold: $('#opt-threshold').checked,
    group_by: linesOf($('#opt-groupby').value.replace(/,/g, '\n')),
  };
  try {
    const data = await call('POST', '/api/synthesize', {
      text: $('#log-text').value,
      format: $('#log-format').value,
      options: options,
    });
    renderFieldAnalysis(data.fields, data.samples);
    renderMessages($('#log-messages'), data.diagnostics);
    state.rule = data.rule;
    state.origin = 'synthesized';
    state.sourceText = $('#log-text').value;
    state.parentId = null;
    writeForm();
    /* The toast says HYPOTHESIS, and the diagnostics panel says which of the
       pinned fields are doubtful. A generated rule that reads like an authored
       one is a generated rule that gets deployed without review. */
    const problems = (data.diagnostics || [])
      .filter(d => d.severity === 'problem').length;
    toast('Proposed a rule from ' + data.samples + ' samples'
          + (problems ? ' with ' + problems + ' thing(s) to check' : '')
          + '. It is a hypothesis \u2014 read the notes before deploying it.',
          problems ? 'bad' : 'good');
    selectTab('build');
    doRender();
  } catch (err) {
    if (!err.handled) throw err;
    /* The field table is cleared on failure. Leaving the previous analysis on
       screen next to a failed run is how an analyst reads one sample's
       results as another's. */
    $('#log-fields').textContent = '';
    renderMessages($('#log-messages'), []);
  }
}

function renderFieldAnalysis(fields, sampleCount) {
  const host = $('#log-fields');
  host.textContent = '';
  host.appendChild(el('div', 'hint', fields.length + ' fields across ' +
                                    sampleCount + ' samples'));
  const table = el('table', 'grid');
  const head = el('tr');
  ['', 'field', 'values', 'present', 'sample'].forEach(c => {
    head.appendChild(el('th', null, c));
  });
  table.appendChild(head);
  fields.forEach(field => {
    const tr = el('tr');
    const mark = el('td', null, field.include ? 'pin' : '\u2014');
    if (field.include) mark.style.color = 'var(--ok)';
    else mark.classList.add('tag-absent');
    tr.appendChild(mark);
    tr.appendChild(el('td', null, field.name));
    tr.appendChild(el('td', 'num', String(field.distinct)));
    tr.appendChild(el('td', 'num', field.present + '/' + field.total));
    const sample = el('td', null, String(JSON.stringify(field.sample)).slice(0, 40));
    if (field.reasons.length) sample.title = field.reasons.join('; ');
    tr.appendChild(sample);
    table.appendChild(tr);
  });
  host.appendChild(table);
  host.appendChild(el('div', 'hint',
    'Hover a sample value to see why a field was skipped.'));
}

async function doSave() {
  try {
    const entry = await call('POST', '/api/history', {
      rule: readRule(),
      origin: state.origin,
      source_text: state.sourceText,
      parent_id: state.parentId,
      note: '',
    });
    /* The saved version becomes the parent of the next save, so a tuning
       session reads as a chain rather than as a pile of unrelated rows. */
    state.parentId = entry.id;
    state.origin = 'authored';
    toast('Saved version ' + entry.id + '. The next save will record itself ' +
          'as derived from it.', 'good');
  } catch (err) {
    if (!err.handled) throw err;
  }
}

async function loadHistory() {
  const params = new URLSearchParams();
  const q = $('#history-q').value.trim();
  if (q) params.set('q', q);
  if ($('#history-origin').value) params.set('origin', $('#history-origin').value);
  if ($('#history-dialect').value) params.set('dialect', $('#history-dialect').value);
  try {
    const data = await call('GET', '/api/history?' + params.toString());
    const host = $('#history-list');
    host.textContent = '';
    if (!data.entries.length) {
      host.appendChild(el('div', 'empty',
        'Nothing saved yet. Save a version from the Build tab.'));
      return;
    }
    data.entries.forEach(entry => {
      const row = el('div', 'entry' +
        (state.selectedEntry === entry.id ? ' sel' : ''));
      row.appendChild(el('span', 'badge ' + entry.origin, entry.origin));
      row.appendChild(el('span', 'e-title',
        entry.title || entry.rule_id || '(untitled)'));
      row.appendChild(el('span', 'e-meta',
        '#' + entry.id + ' \u00b7 ' + entry.dialect + ' \u00b7 ' +
        entry.created_at.replace('T', ' ').replace('+00:00', 'Z')));
      row.onclick = () => openEntry(entry.id);
      host.appendChild(row);
    });
  } catch (err) {
    if (!err.handled) throw err;
  }
}

async function openEntry(entryId) {
  try {
    const entry = await call('GET', '/api/history/' + entryId);
    const lineage = await call('GET', '/api/history/' + entryId + '/lineage');

    state.rule = entry.rule;
    state.dialect = entry.dialect || state.dialect;
    state.parentId = entry.id;
    state.origin = 'authored';
    state.sourceText = entry.source_text || '';
    state.selectedEntry = entry.id;
    $('#dialect').value = state.dialect;
    writeForm();

    const host = $('#history-lineage');
    host.textContent = '';
    host.appendChild(el('div', 'hint',
      lineage.lineage.length + ' version(s), oldest first \u2014 the order ' +
      'the tuning happened in.'));
    lineage.lineage.forEach(version => {
      const box = el('div', 'ol-stage');
      const head = el('div');
      head.appendChild(el('span', 'badge ' + version.origin, version.origin));
      head.appendChild(el('span', 'ol-kind',
        ' #' + version.id + ' ' + (version.title || version.rule_id)));
      box.appendChild(head);
      box.appendChild(el('div', 'hint',
        version.created_at.replace('T', ' ').replace('+00:00', 'Z')));
      if (version.note) box.appendChild(el('div', 'ol-expr', version.note));
      if (version.id === entry.id) box.style.borderLeftColor = 'var(--accent)';
      host.appendChild(box);
    });

    if (entry.source_text) {
      host.appendChild(el('h3', null, 'as originally pasted'));
      const pre = el('pre', 'code', entry.source_text);
      host.appendChild(pre);
    }

    loadHistory();
    toast('Version ' + entry.id + ' loaded into the builder. Saving will ' +
          'record a new version derived from it.', 'good');
  } catch (err) {
    if (!err.handled) throw err;
  }
}

/* ------------------------------------------------------------------- start */

function bind() {
  /* The primary tabs carry `data-main`, not `data-pane`: clicking Studio
     returns to the section you were last in rather than always to the first
     one, which is what a two-level header has to do to not lose your place. */
  $('#tabs').addEventListener('click', event => {
    const tab = event.target.closest('.tab');
    if (!tab || !event.currentTarget.contains(tab)) return;
    selectTab(tab.dataset.main === 'home' ? 'home' : (state.studioPane || 'build'));
  });
  /* A click on a label that contains a child element still resolves to the
     button, which is how the rail's own tabs were silently unclickable. */
  $('#subtabs').addEventListener('click', event => {
    const tab = event.target.closest('.tab');
    if (!tab || !event.currentTarget.contains(tab)) return;
    selectTab(tab.dataset.pane);
  });
  $('#dialect').onchange = () => {
    state.dialect = $('#dialect').value;
    /* Re-rendered, not left alone. Switching Sentinel to Splunk used to leave
       KQL on screen under a dropdown reading Splunk -- the label contradicting
       the content, which is worse than showing nothing. */
    scheduleRender();
  };
  /* Any edit anywhere in the builder makes the rendered pane stale. Bound on
     the pane rather than on each control, because a new control is added
     every time a stage is added and a per-control binding would miss them --
     which is how the staleness survived: the handlers that existed did not
     cover the inputs created later. */
  const builder = $('#pane-build');
  if (builder) {
    builder.addEventListener('input', event => {
      if (event.target.closest('#events, #events-format')) return;
      scheduleRender();
    });
    builder.addEventListener('change', event => {
      if (event.target.closest('#events, #events-format')) return;
      scheduleRender();
    });
  }
  /* Changing the SAMPLE invalidates the verdict but not the rendered rule --
     the query is unchanged, the evidence it was judged against is not. Bound
     separately so editing a sample does not fire a render round trip. */
  ['#events', '#events-format'].forEach(selector => {
    const node = $(selector);
    if (!node) return;
    const invalidate = () => {
      const verdict = $('#evaluation');
      if (verdict && verdict.innerHTML.trim()
          && !verdict.classList.contains('stale')) {
        verdict.classList.add('stale');
        verdict.insertBefore(
          el('div', 'stale-note',
             'The sample has changed \u2014 this verdict is about the '
             + 'PREVIOUS one. Press Run again.'),
          verdict.firstChild);
      }
    };
    node.addEventListener('input', invalidate);
    node.addEventListener('change', invalidate);
  });
  $('#add-stage').onclick = () => {
    const kind = $('#add-stage-kind').value;
    const stages = state.rule.rule.pipeline.v;
    /* Before the Emit, always: a stage after the output is a stage that never
       runs, and the rule would look right while doing something else. */
    const emitAt = stages.findIndex(s => s['@'] === 'Emit');
    const at = emitAt < 0 ? stages.length : emitAt;
    stages.splice(at, 0, newStage(kind, stages.length));
    renderStages();
  };
  $('#render').onclick = doRender;
  $('#validate').onclick = doValidate;
  $('#run').onclick = doRun;
  $('#run-save-evidence').onclick = () => saveEvidence('#evaluation');
  $('#save').onclick = doSave;
  $('#import-go').onclick = doImport;
  $('#log-go').onclick = doFromLog;
  $('#history-refresh').onclick = loadHistory;
  $('#history-q').onkeydown = event => {
    if (event.key === 'Enter') loadHistory();
  };
  $('#history-origin').onchange = loadHistory;
  $('#history-dialect').onchange = loadHistory;

  $('#dataset-save').onclick = doDatasetSave;
  $('#dataset-refresh').onclick = loadDatasets;
  $('#dataset-search').onclick = loadDatasets;
  $('#dataset-q').onkeydown = event => {
    if (event.key === 'Enter') loadDatasets();
  };
  $('#build-dataset').onchange = event => {
    state.selectedDatasetId = Number(event.target.value) || null;
  };
  $('#test-run-dataset').onchange = event => {
    state.selectedDatasetId = Number(event.target.value) || null;
  };
  $('#test-run-save').onclick = doTestRunSave;
  $('#test-run-refresh').onclick = loadTestRuns;

  /* The start pane. */
  $('#home-example').onclick = loadExample;
  $('#home-blank').onclick = startBlank;
  $('#brand').onclick = () => selectTab('home');
  document.querySelectorAll('.home-cards .card, .home-cta [data-goto]').forEach(card => {
    card.onclick = () => selectTab(card.dataset.goto);
  });
}

(async function start() {
  bind();
  writeForm();
  try {
    await loadDialects();
    await loadDatasets();
    await loadTestRuns();
  } catch (err) { /* already reported */ }
})();
