/* The condition editor.

   A condition is an expression tree, not a flat row: `A and (B or C)` is a
   real thing an analyst writes, and flattening it silently changes the rule.
   Each node therefore draws itself and asks its parent to replace it — no node
   needs to know its own address in the tree. */

import { h } from './dom.js';
import { btn } from './components.js';
import { state, touch } from '../core/state.js';
import {
  T, boolOp, comparison, describeExpr, fieldRef,
  fieldRefText, literal, literalFromText, literalToText, newComparison,
} from '../core/ir.js';

export function conditionEditor(expr, onChange, options) {
  const host = h('div', { class: 'cond-list' });
  renderCondition(host, expr, onChange, options || {});
  return host;
}

/* The operator list the form offers, taken from the engine.

   `/api/vocabulary` builds it by asking the parser and every renderer what
   they actually support. The page used to hold its own copy, and that copy
   was missing `has` while offering `contains_any` -- an operator the parser
   cannot read, which then produced a refusal blaming the FIELD. */
function operatorOptions(current) {
  const rows = (state.cache.vocabulary && state.cache.vocabulary.operators) || [];
  const ready = (state.cache.dialects || []).filter((d) => d.status === 'ready').length;
  const options = rows.map((row) => ({
    value: row.op,
    label: row.readable === false
      ? row.op + '  \u2014 cannot be read back'
      : row.op + '  (' + row.targets.length + ' of ' + (ready || 8) + ' targets)',
    title: row.readable === false
      ? 'this build cannot read this operator back, so a rule using it cannot be edited here'
      : 'writable in ' + (row.targets.join(', ') || 'no target'),
  }));

  if (!rows.length) {
    /* The catalogue has not arrived. Offer the operator the rule already uses
       and nothing else, rather than an empty select that would rewrite it. */
    return [{ value: current, label: current }];
  }

  if (current && !options.some((option) => option.value === current)) {
    /* An imported rule can carry an operator the form does not offer. It has
       to stay selectable: a <select> with no matching option displays its
       first entry, and the next keystroke would rewrite the operator. */
    options.unshift({
      value: current,
      label: current + '  (imported, not offered)',
      title: 'this operator came from the imported rule and cannot be rebuilt here',
    });
  }
  return options;
}

export function renderCondition(host, expr, replace, options) {
  host.textContent = '';
  if (!expr) {
    host.appendChild(btn('+ condition', {
      size: 'sm', kind: 'quiet',
      onClick: () => { replace(newComparison()); },
    }));
    return;
  }

  const kind = expr['@'];

  if (kind === 'BoolOp') {
    const wrap = h('div', { class: 'cond-group' });
    const head = h('div', { class: 'cond-row is-group' });
    const op = h('button', {
      class: 'cond-op',
      type: 'button',
      title: 'switch between AND and OR',
      text: expr.op.v.toUpperCase(),
      on: {
        click: () => {
          expr.op = T.str(expr.op.v === 'and' ? 'or' : 'and');
          touch();
          renderCondition(host, expr, replace, options);
        },
      },
    });
    head.appendChild(h('div', { class: 'row' }, op,
      btn('+', {
        size: 'sm', kind: 'quiet', title: 'add another condition to this group',
        onClick: () => {
          expr.operands.v.push(newComparison());
          touch();
          renderCondition(host, expr, replace, options);
        },
      }),
      btn('ungroup', {
        size: 'sm', kind: 'quiet',
        title: 'collapse this group into a single condition',
        onClick: () => {
          /* An empty group is the always-true predicate, which would match
             everything, so it collapses to its first operand. */
          replace(expr.operands.v.length ? expr.operands.v[0] : newComparison());
        },
      })));
    head.appendChild(h('span', { class: 'muted mono', text: expr.operands.v.length + ' conditions' }));
    wrap.appendChild(head);

    expr.operands.v.forEach((operand, index) => {
      const slot = h('div');
      renderCondition(slot, operand, (next) => {
        if (next === null) {
          expr.operands.v.splice(index, 1);
          touch();
          if (expr.operands.v.length === 0) { replace(newComparison()); return; }
          if (expr.operands.v.length === 1) { replace(expr.operands.v[0]); return; }
        } else {
          expr.operands.v[index] = next;
          touch();
        }
        renderCondition(host, expr, replace, options);
      }, options);
      wrap.appendChild(slot);
    });
    host.appendChild(wrap);
    return;
  }

  if (kind === 'Not') {
    const wrap = h('div', { class: 'cond-group' });
    wrap.appendChild(h('div', { class: 'row' },
      h('span', { class: 'cond-op', text: 'NOT' }),
      btn('remove not', {
        size: 'sm', kind: 'quiet',
        onClick: () => { replace(expr.operand); },
      })));
    const slot = h('div');
    renderCondition(slot, expr.operand, (next) => {
      if (next === null) { replace(null); return; }
      expr.operand = next;
      touch();
      renderCondition(host, expr, replace, options);
    }, options);
    wrap.appendChild(slot);
    host.appendChild(wrap);
    return;
  }

  if (kind === 'Comparison') {
    const row = h('div', { class: 'cond-row' });

    const scope = h('select', {
      class: 'select',
      'aria-label': 'Which row this field is read from',
      title: 'left and right are the two sides of a join and mean nothing ' +
        'outside one',
    });
    for (const value of ['current', 'left', 'right']) {
      const option = h('option', { value, text: value });
      if (expr.left['@'] === 'FieldRef' && expr.left.scope.v === value) {
        option.selected = true;
      }
      scope.appendChild(option);
    }
    scope.onchange = () => {
      expr.left = fieldRef(fieldRefText(expr.left), scope.value);
      touch();
    };
    row.appendChild(scope);

    const name = h('input', {
      class: 'input code',
      type: 'text',
      value: fieldRefText(expr.left),
      placeholder: 'win.eventdata.Image',
      'aria-label': 'Condition field name',
      on: {
        change: () => {
          expr.left = fieldRef(name.value, scope.value);
          touch();
        },
      },
    });
    row.appendChild(name);

    const op = h('select', {
      class: 'select',
      'aria-label': 'Condition operator',
    });
    for (const choice of operatorOptions(expr.op.v)) {
      const option = h('option', {
        value: choice.value,
        text: choice.label,
        title: choice.title || null,
      });
      if (expr.op.v === choice.value) option.selected = true;
      op.appendChild(option);
    }
    op.onchange = () => { expr.op = T.str(op.value); touch(); };
    row.appendChild(op);

    /* A Regex is shown as its pattern and edited back into a Regex. Showing it
       as an empty box hid the pattern and silently turned a case-insensitive
       suffix test into a case-sensitive exact match. */
    const isRegex = expr.right['@'] === 'Regex';
    const value = h('input', {
      class: 'input code',
      type: 'text',
      'aria-label': 'Comparison value',
      placeholder: 'value',
      value: isRegex
        ? expr.right.pattern.v
        : (expr.right['@'] === 'Literal' ? literalToText(expr.right.value) : ''),
      title: isRegex
        ? 'a ' + expr.right.dialect.v + ' pattern' +
          (expr.right.nocase.v ? ', matched without regard to case' : '')
        : 'numbers are sent as exact decimals, never as floats',
      on: {
        change: () => {
          if (isRegex) {
            expr.right = {
              '@': 'Regex',
              pattern: T.str(value.value),
              dialect: expr.right.dialect,
              nocase: expr.right.nocase,
            };
          } else {
            expr.right = literal(literalFromText(value.value));
          }
          touch();
        },
      },
    });
    row.appendChild(value);

    const actions = h('div', { class: 'cond-actions' },
      /* A condition still holding the placeholder field is not an error — it
         is unfinished, and it makes every row undecided. Say so on the row
         rather than letting the verdict explain it three screens later. */
      expr.left['@'] === 'FieldRef' && expr.left.name.v === 'FieldName'
        ? h('span', {
          class: 'badge caution',
          text: 'placeholder',
          title: 'FieldName is a placeholder. Replace it with a real field, or ' +
            'this condition makes every event undecided.',
        })
        : null,
      btn(expr.negate.v ? 'NOT' : 'not', {
        size: 'sm', kind: 'quiet', title: 'negate this comparison',
        active: expr.negate.v,
        onClick: () => {
          expr.negate = T.bool(!expr.negate.v);
          touch();
          renderCondition(host, expr, replace, options);
        },
      }),
      btn('and', {
        size: 'sm', kind: 'quiet', title: 'group this with another condition',
        onClick: () => { replace(boolOp('and', [expr, newComparison()])); },
      }),
      btn('\u00d7', {
        size: 'sm', kind: 'quiet', title: 'remove this condition',
        onClick: () => { replace(null); },
      }));

    if (isRegex) {
      actions.insertBefore(h('span', {
        class: 'badge',
        text: expr.right.nocase.v ? 'regex \u00b7 any case' : 'regex',
        title: expr.right.dialect.v + (expr.right.nocase.v
          ? ' \u2014 this pattern ignores upper and lower case'
          : ' \u2014 this pattern is case-sensitive'),
      }), actions.firstChild);
    }
    row.appendChild(actions);
    host.appendChild(row);
    return;
  }

  /* Anything the editor cannot draw is kept and shown read-only rather than
     dropped: a pasted rule can contain a Span, a SubQuery or a Call, and
     discarding it on load would hand back a different rule. */
  const row = h('div', { class: 'cond-row is-group' },
    h('span', { class: 'cond-readonly', text: describeExpr(expr) }),
    h('div', { class: 'cond-actions' },
      h('span', {
        class: 'badge caution',
        text: kind,
        title: 'this node is kept exactly as imported; the form cannot edit it ' +
          'yet, so it is shown rather than dropped',
      }),
      btn('\u00d7', {
        size: 'sm', kind: 'quiet',
        onClick: () => { replace(null); },
      })));
  host.appendChild(row);
}

export { comparison, fieldRef, literal, newComparison };
