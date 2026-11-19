/* The rule model: the engine's tagged IR, and nothing else.

   `state.doc.payload` IS the payload `/api/lower` returns and `/api/render`
   accepts. There is no second, browser-side rule shape, because that is how a
   form ends up showing one thing while the rendered rule says another. */

export const T = {
  str: (v) => ({ '@': 'str', v: String(v) }),
  int: (v) => ({ '@': 'int', v: Math.trunc(v) }),
  bool: (v) => ({ '@': 'bool', v: !!v }),
  dec: (v) => ({ '@': 'decimal', v: String(v) }),
  nul: () => ({ '@': 'null' }),
  absent: () => ({ '@': 'absent' }),
  tuple: (items) => ({ '@': 'tuple', v: items }),
  list: (items) => ({ '@': 'list', v: items }),
  dict: (pairs) => ({ '@': 'dict', v: pairs }),
  cap: (v) => ({ '@': 'capability', v: v || 'evaluated' }),
};

/* The operator vocabulary is NOT here. It comes from `/api/vocabulary`, built
   by the engine from what the parser and the renderers actually support. A
   copy in this file was the fourth one, and it had already drifted. */

export const MEASURE_FUNCTIONS = [
  'count', 'count_if', 'dcount', 'sum', 'min', 'max', 'avg', 'stdev',
  'percentile', 'arg_max', 'arg_min', 'earliest', 'latest',
  'make_set', 'make_list',
];

/** A JS value out of a tagged node, for display. */
export function plain(node) {
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

/** Numbers become decimals, never floats: thresholds are Decimal end to end. */
export function literalFromText(text) {
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

export function literalToText(node) {
  if (!node) return '';
  const tag = node['@'];
  if (tag === 'null') return 'null';
  if (tag === 'absent') return '';
  if (tag === 'bool') return node.v ? 'true' : 'false';
  return String(node.v);
}

export function node(kind, fields) {
  return Object.assign(
    { '@': kind, id: T.str(fields.id || ''), capability: T.cap(), note: T.str('') },
    fields,
  );
}

export function fieldRef(name, scope) {
  const parts = String(name || '').split('.').filter((p) => p !== '');
  const head = parts.length ? parts[0] : 'field';
  return {
    '@': 'FieldRef',
    name: T.str(head),
    path: T.tuple(parts.slice(1).map(T.str)),
    scope: T.str(scope || 'current'),
  };
}

export function fieldRefText(ref) {
  if (!ref || ref['@'] !== 'FieldRef') return '';
  const path = (ref.path && ref.path.v ? ref.path.v : []).map((p) => p.v);
  return [ref.name.v].concat(path).join('.');
}

export function comparison(op, left, right) {
  return {
    '@': 'Comparison', op: T.str(op), left, right, negate: T.bool(false),
    /* `nocase` is a real field on the IR and the evaluator honours it. Leaving
       it out of the wire object meant the workbench sent a Comparison the
       decoder had to fill in, and a case-insensitive test written here came
       back case-sensitive -- the flag was silently reset on every save. */
    nocase: T.bool(false),
  };
}

export const literal = (value) => ({ '@': 'Literal', value });

/** The placeholder comparison in a blank rule.

    The value is not empty on purpose: an empty literal is the one shape every
    backend refuses (Wazuh's empty matcher fires on everything, Sigma's empty
    detection item matches nothing sensibly), so a brand-new rule would arrive
    already unable to render. `FieldName == "value"` renders in all eight
    languages and reads, correctly, as something to replace. */
export const newComparison = () =>
  comparison('==', fieldRef('FieldName'), literal(T.str('value')));

export const boolOp = (op, operands) =>
  ({ '@': 'BoolOp', op: T.str(op), operands: T.tuple(operands) });

/** A minimal valid rule: source, one comparison, output. */
export function emptyRule() {
  return {
    schema: 1,
    rule: {
      '@': 'Rule',
      rule_id: T.str('new-rule'),
      pipeline: T.tuple([
        node('Read', {
          id: T.str('source'), table: T.str('SecurityEvent'),
          selector: T.str(''), time_field: T.str(''),
        }),
        node('Filter', { id: T.str('where_1'), condition: newComparison() }),
        node('Emit', { id: T.str('out'), keeps: T.tuple([]), dedupe_by: T.tuple([]) }),
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

    The IR refuses half-built nodes, so these defaults are real values rather
    than blanks. */
export function newStage(kind, index) {
  const id = kind.toLowerCase() + '_' + index;
  switch (kind) {
    case 'Filter':
      return node('Filter', { id: T.str(id), condition: newComparison() });
    case 'Aggregate':
      return node('Aggregate', {
        id: T.str(id),
        measures: T.tuple([{
          '@': 'Measure', function: T.str('count'), name: T.str('Hits'),
          field: T.nul(), distinct: T.bool(false), param: T.nul(),
        }]),
        keys: T.tuple([fieldRef('Computer')]),
        window: T.nul(),
      });
    case 'Derive':
      return node('Derive', {
        id: T.str(id),
        assignments: T.tuple([T.tuple([T.str('NewColumn'), literal(T.str(''))])]),
        kind: T.str('add'),
      });
    case 'Project':
      return node('Project', {
        id: T.str(id), renames: T.tuple([]), drops: T.tuple([]),
        keeps: T.tuple([fieldRef('Computer')]),
      });
    case 'Sort':
      return node('Sort', {
        id: T.str(id),
        keys: T.tuple([T.tuple([fieldRef('Computer'), T.bool(true)])]),
        limit: T.nul(),
      });
    case 'Limit':
      return node('Limit', { id: T.str(id), count: T.int(100), keep_last: T.bool(false) });
    case 'Distinct':
      return node('Distinct', { id: T.str(id), keys: T.tuple([fieldRef('Computer')]) });
    case 'Expand':
      return node('Expand', { id: T.str(id), field: fieldRef('Values'), into: T.str('') });
    case 'Correlation':
      return node('Correlation', {
        id: T.str(id), parent: T.str('source'), frequency: T.int(5),
        timeframe: { '@': 'Duration', seconds: T.dec('300') },
        group_by: T.tuple([fieldRef('Computer')]),
        count_subject: T.str('parent'),
      });
    case 'Sequence':
      return node('Sequence', {
        id: T.str(id),
        steps: T.tuple([
          { '@': 'SequenceStep', condition: newComparison(), runs: T.int(1) },
          { '@': 'SequenceStep', condition: newComparison(), runs: T.int(1) },
        ]),
        by: T.tuple([fieldRef('Computer')]),
        maxspan: { '@': 'Duration', seconds: T.dec('300') },
        until: T.nul(),
      });
    default:
      throw new Error(kind + ' is not a stage this builder creates');
  }
}

/** Readable text for a node the form cannot draw. Display only. */
export function describeExpr(expr) {
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
  if (kind === 'ListExpr') return '[' + expr.items.v.map(describeExpr).join(', ') + ']';
  if (kind === 'Regex') {
    return '/' + expr.pattern.v + '/' + expr.dialect.v +
      (expr.nocase.v ? ' nocase' : '');
  }
  if (kind === 'Call') {
    return expr.function.v + '(' + expr.args.v.map(describeExpr).join(', ') + ')';
  }
  if (kind === 'SubQuery') return '[ ' + expr.pipeline.v.length + ' stages ]';
  if (kind === 'Duration') return expr.seconds.v + 's';
  return kind;
}

export const linesOf = (text) =>
  String(text).split('\n').map((l) => l.trim()).filter(Boolean);

/** The nine stages that are not the ordinary filter, with the sentence that
    tells an analyst which one they want. Used by the Stage Library. */
export const STAGE_LIBRARY = [
  {
    kind: 'Filter',
    what: 'Keep only the events that match a condition. Most rules are one of these.',
    example: 'EventID == 4688 AND CommandLine contains "powershell"',
    needs: 'scope, field, operator, value',
  },
  {
    kind: 'Aggregate',
    what: 'Group events and compute a number per group — "how many times".',
    example: 'count() by Account, IpAddress → Attempts',
    needs: 'measures, group-by fields, optional time window',
  },
  {
    kind: 'Correlation',
    what: 'Fire when the same parent rule matches N times inside a timeframe.',
    example: 'parent match × 5 within 300s, grouped by Computer',
    needs: 'parent, frequency, timeframe, group-by',
  },
  {
    kind: 'Sequence',
    what: 'This happened, then that happened — order is part of the detection.',
    example: 'procdump.exe, then lsass.exe access, within 300s',
    needs: 'two or more steps, join key, max span, optional cancellation',
  },
  {
    kind: 'Distinct',
    what: 'Drop duplicate rows, keeping one per combination of fields.',
    example: 'distinct on Account, IpAddress',
    needs: 'distinct-on fields',
  },
  {
    kind: 'Project',
    what: 'Choose, drop or rename the columns that come out.',
    example: 'keep Computer, Account; rename Computer → Host',
    needs: 'keep list, or drop list, plus optional renames',
  },
  {
    kind: 'Derive',
    what: 'Compute a new column from a value.',
    example: 'SeverityScore = 10',
    needs: 'one or more target = value pairs',
  },
  {
    kind: 'Sort',
    what: 'Order the results before they are limited or returned.',
    example: 'by Hits descending',
    needs: 'sort keys and a direction each',
  },
  {
    kind: 'Limit',
    what: 'Keep only the first or last N rows.',
    example: 'first 100 rows',
    needs: 'a count and first/last',
  },
  {
    kind: 'Expand',
    what: 'Turn a list-valued field into one row per item.',
    example: 'expand Values into CommandLine',
    needs: 'the list field, and an optional target name',
  },
];

/** Four working rules offered on Start. They are sent through `/api/lower`
    rather than hand-built as IR, so a template that no longer parses is
    caught by the same code path the analyst uses. */
export const TEMPLATES = [
  {
    id: 'encoded-powershell',
    title: 'Encoded PowerShell',
    body: 'A process started PowerShell with a base64-encoded command — the ' +
      'shape of most droppers and many hands-on-keyboard attacks.',
    dialect: 'sentinel',
    text: [
      '// title: Encoded PowerShell command line',
      '// description: PowerShell started with a base64-encoded command.',
      '// severity: high',
      '// author: template',
      'SecurityEvent',
      '| where EventID == 4688',
      '| where NewProcessName endswith "powershell.exe"',
      '| where CommandLine contains "-enc"',
    ].join('\n'),
  },
  {
    id: 'brute-force',
    title: 'Failed logon burst',
    body: 'The same account failed to log on more than five times, grouped by ' +
      'source address — password guessing rather than a typo.',
    dialect: 'sentinel',
    text: [
      '// title: Failed logon burst from one account',
      '// severity: medium',
      '// author: template',
      'SecurityEvent',
      '| where EventID == 4625',
      '| summarize Attempts = count() by Account, IpAddress',
      '| where Attempts > 5',
    ].join('\n'),
  },
  {
    id: 'new-service',
    title: 'New service installed',
    body: 'A service was installed. Persistence and privilege escalation both ' +
      'arrive this way, and it is rare on a workstation.',
    dialect: 'sentinel',
    text: [
      '// title: New Windows service installed',
      '// severity: medium',
      '// author: template',
      'SecurityEvent',
      '| where EventID == 7045',
      '| where ServiceType contains "kernel"',
    ].join('\n'),
  },
  {
    id: 'scheduled-task',
    title: 'Scheduled task created',
    body: 'A scheduled task was registered. Legitimate in most estates, so the ' +
      'conditions are the interesting part — edit them.',
    dialect: 'sentinel',
    text: [
      '// title: Scheduled task registered',
      '// severity: low',
      '// author: template',
      'SecurityEvent',
      '| where EventID == 4698',
      '| where TaskContent contains "powershell"',
    ].join('\n'),
  },
];

export const EXAMPLE_SAMPLE =
  '{"EventID": 4656, "ObjectName": "C:\\\\Windows\\\\System32\\\\lsass.exe", ' +
  '"AccessMask": "0x1410", "Computer": "WS-01", "TimeGenerated": 1767182400}';
