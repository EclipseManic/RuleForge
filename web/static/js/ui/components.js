/* Reusable pieces. Every screen is built from these, so a change to how a
   field or a verdict looks happens once. */

import { h } from './dom.js';

/* -- buttons -------------------------------------------------------------- */

export function btn(label, options) {
  const opts = options || {};
  const classes = ['btn'];
  if (opts.kind) classes.push(opts.kind);
  if (opts.size === 'sm') classes.push('sm');
  if (opts.block) classes.push('block');
  if (opts.active) classes.push('is-on');
  if (opts.title) classes.push('icon');
  return h('button', {
    class: classes.join(' '),
    id: opts.id || null,
    type: opts.type || 'button',
    title: opts.title || null,
    disabled: opts.disabled || false,
    'aria-label': opts.ariaLabel || null,
    on: { click: opts.onClick },
  }, label, opts.after || null);
}

/* -- fields --------------------------------------------------------------- */

export function field(options) {
  const opts = options || {};
  const wrap = h('label', {
    class: 'field' + (opts.error ? ' has-error' : ''),
  });
  if (opts.label) {
    wrap.appendChild(h('span', { class: 'field-label', text: opts.label }));
  }
  wrap.appendChild(opts.control);
  if (opts.hint) {
    wrap.appendChild(h('span', { class: 'field-hint', text: opts.hint }));
  }
  if (opts.error) {
    wrap.appendChild(h('span', { class: 'field-error', text: opts.error }));
  }
  return wrap;
}

export function input(options) {
  const opts = options || {};
  return h('input', {
    class: 'input' + (opts.code ? ' code' : ''),
    id: opts.id || null,
    type: opts.type || 'text',
    value: opts.value === null || opts.value === undefined ? '' : opts.value,
    placeholder: opts.placeholder || null,
    spellcheck: false,
    autocomplete: 'off',
    on: {
      input: opts.onInput,
      change: opts.onChange,
      keydown: opts.onKeydown,
      blur: opts.onBlur,
    },
  });
}

export function textarea(options) {
  const opts = options || {};
  return h('textarea', {
    class: 'textarea' + (opts.code ? ' code' : ''),
    id: opts.id || null,
    rows: opts.rows || 6,
    placeholder: opts.placeholder || null,
    spellcheck: false,
    value: opts.value || '',
    on: {
      input: opts.onInput,
      change: opts.onChange,
      keydown: opts.onKeydown,
    },
  });
}

export function select(options) {
  const opts = options || {};
  const node = h('select', {
    class: 'select',
    id: opts.id || null,
    on: { change: opts.onChange },
  });
  for (const option of opts.options || []) {
    const value = typeof option === 'string' ? option : option.value;
    const label = typeof option === 'string' ? option : option.label;
    const item = h('option', {
      value,
      text: label,
      disabled: option.disabled || false,
      title: option.title || null,
    });
    if (String(value) === String(opts.value)) item.selected = true;
    node.appendChild(item);
  }
  return node;
}

export function checkbox(options) {
  const opts = options || {};
  return h('label', { class: 'check' },
    h('input', {
      type: 'checkbox',
      id: opts.id || null,
      checked: !!opts.checked,
      on: { change: opts.onChange },
    }),
    opts.label || '');
}

/* -- containers ----------------------------------------------------------- */

export function card(options) {
  const opts = options || {};
  const node = h('section', { class: 'card' + (opts.class ? ' ' + opts.class : '') });
  if (opts.title || opts.actions) {
    node.appendChild(h('div', { class: 'card-head' },
      h('div', { class: 'grow' },
        h('h2', { text: opts.title || '' }),
        opts.sub ? h('div', { class: 'card-sub', text: opts.sub }) : null),
      opts.actions || null));
  }
  if (opts.body) {
    node.appendChild(h('div', { class: 'card-body' + (opts.tight ? ' tight' : '') }, opts.body));
  }
  if (opts.foot) node.appendChild(h('div', { class: 'card-foot' }, opts.foot));
  return node;
}

export function pageHead(options) {
  const opts = options || {};
  return h('div', { class: 'page-head' },
    h('div', { class: 'grow' },
      h('span', { class: 'eyebrow', text: opts.eyebrow || '' }),
      h('h1', { text: opts.title }),
      opts.sub ? h('p', { class: 'page-sub', text: opts.sub }) : null),
    opts.actions ? h('div', { class: 'btn-row' }, opts.actions) : null);
}

export function emptyBox(options) {
  const opts = options || {};
  return h('div', { class: 'empty' },
    opts.title ? h('div', { class: 'empty-title', text: opts.title }) : null,
    h('div', { text: opts.body || '' }),
    opts.action || null);
}

export function badge(label, kind, title) {
  return h('span', {
    class: 'badge' + (kind ? ' ' + kind : ''),
    text: label,
    title: title || null,
  });
}

export function kv(pairs) {
  const list = h('dl', { class: 'kv' });
  for (const [term, value] of pairs) {
    list.appendChild(h('dt', { text: term }));
    list.appendChild(h('dd', {}, value instanceof Node ? value : String(value)));
  }
  return list;
}

/* -- tables --------------------------------------------------------------- */

export function dataTable(options) {
  const opts = options || {};
  const table = h('table', { class: 'table' + (opts.class ? ' ' + opts.class : '') });
  if (opts.columns) {
    table.appendChild(h('thead', {},
      h('tr', {}, opts.columns.map((column) => h('th', {
        class: column.align === 'right' ? 'num' : null,
        text: column.label,
      })))));
  }
  const body = h('tbody');
  for (const row of opts.rows || []) {
    body.appendChild(h('tr', {}, row.map((cell, index) => {
      const column = (opts.columns || [])[index] || {};
      return h('td', {
        class: column.align === 'right' ? 'num' : null,
      }, cell instanceof Node ? cell : String(cell ?? ''));
    })));
  }
  table.appendChild(body);
  return opts.wrap === false ? table : h('div', { class: 'table-wrap' }, table);
}

/* -- code ----------------------------------------------------------------- */

export function codeBlock(options) {
  const opts = options || {};
  const wrap = h('div', { class: 'code', id: opts.containerId || null });
  if (opts.label || opts.copy) {
    wrap.appendChild(h('div', { class: 'code-head' },
      h('span', { class: 'grow', id: opts.labelId || null, text: opts.label || '' }),
      opts.copy !== false
        ? btn('Copy', {
          size: 'sm', kind: 'quiet',
          onClick: () => copyText(opts.text || ''),
        })
        : null));
  }
  const pre = h('pre', { id: opts.id || null, text: opts.text || '\u2014' });
  wrap.appendChild(pre);
  return wrap;
}

export async function copyText(value) {
  try {
    await navigator.clipboard.writeText(String(value));
    toast('Copied to the clipboard.', 'good');
  } catch (err) {
    toast('The browser refused clipboard access. Select the text and copy it.', 'bad');
  }
}

/* -- verdict and trace ---------------------------------------------------- */

const VERDICT_NOTE = {
  matched: 'At least one event survived every stage.',
  no_match: 'Every event was dropped. The rule ran, and the answer is a real no.',
  not_evaluated: 'Something in the rule could not be decided from these events, ' +
    'so "no match" would be a guess.',
};

export function verdictBox(result) {
  const verdict = result && result.verdict ? result.verdict : 'not_evaluated';
  const word = {
    matched: 'Matched',
    no_match: 'No match',
    not_evaluated: 'Could not tell',
  }[verdict] || verdict;
  return h('div', { class: 'verdict ' + verdict },
    h('span', { class: 'verdict-word', text: word }),
    h('span', { class: 'verdict-note', text: VERDICT_NOTE[verdict] || '' }));
}

export function traceView(result) {
  const rows = (result && result.rows) || [];
  const trace = (result && result.trace) || [];
  const wrap = h('div', { class: 'stack' });

  /* The sieve: one number per stage, so the stage that dropped the rows is
     visible before reading a table. */
  const start = trace.length ? trace[0].rows_in : 0;
  const sieve = h('div', { class: 'sieve' });
  sieve.appendChild(h('span', { class: 'sieve-cell', text: String(start) + ' in' }));
  trace.forEach((step, index) => {
    sieve.appendChild(h('span', { class: 'sieve-arrow', text: '\u2192' }));
    const cell = h('span', {
      class: 'sieve-cell' + (index === trace.length - 1 ? ' is-last' : ''),
      title: step.dropped > 0
        ? step.dropped + ' row(s) dropped here'
        : 'nothing dropped here',
      text: String(step.rows_out),
    });
    if (step.dropped > 0) cell.dataset.dropped = String(step.dropped);
    sieve.appendChild(cell);
  });
  sieve.appendChild(h('span', {
    class: 'muted mono',
    text: rows.length + ' row(s) out',
  }));
  wrap.appendChild(sieve);

  const max = Math.max(1, ...trace.map((step) => step.rows_in));
  const list = h('div', { class: 'trace' });
  for (const step of trace) {
    list.appendChild(h('div', { class: 'trace-row' },
      h('span', { class: 'trace-name', text: step.stage, title: step.stage }),
      h('span', { class: 'trace-kind', text: step.kind }),
      h('div', { class: 'trace-bar' },
        h('div', {
          class: 'trace-fill',
          style: { width: Math.round((step.rows_out / max) * 100) + '%' },
        })),
      h('span', { class: 'trace-counts' },
        String(step.rows_in) + ' \u2192 ' + String(step.rows_out),
        step.dropped > 0
          ? h('span', { class: 'trace-drop', text: ' \u2212' + step.dropped })
          : null,
        step.undecided > 0
          ? h('span', { class: 'trace-undecided', text: ' ?' + step.undecided })
          : null)));
  }
  wrap.appendChild(list);
  return wrap;
}

/* -- toast ---------------------------------------------------------------- */

let toastTimer = null;

export function toast(message, kind, code) {
  let box = document.querySelector('#toast');
  if (!box) {
    box = h('div', { id: 'toast', class: 'toast' });
    document.body.appendChild(box);
  }
  box.className = 'toast' + (kind ? ' ' + kind : '');
  box.textContent = '';
  if (code) box.appendChild(h('code', { text: code }));
  box.appendChild(h('span', { text: message }));
  box.hidden = false;
  box.onclick = () => { box.hidden = true; };
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { box.hidden = true; }, kind === 'bad' ? 11000 : 5000);
}

/* -- misc ----------------------------------------------------------------- */

export function section(title, sub) {
  return h('div', { class: 'stack' },
    h('span', { class: 'eyebrow', text: title }),
    sub ? h('p', { class: 'page-sub', text: sub }) : null);
}

export function spinner(label) {
  return h('div', { class: 'empty' }, h('div', { text: label || 'Working\u2026' }));
}
