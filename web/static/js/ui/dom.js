/* DOM construction. Nodes only — no innerHTML anywhere, so a rule title
   containing markup can never become markup. */

export function h(tag, props, ...children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'on') {
        for (const [event, handler] of Object.entries(value)) {
          if (handler) node.addEventListener(event, handler);
        }
      } else if (key === 'data') {
        for (const [name, v] of Object.entries(value)) node.dataset[name] = v;
      } else if (key === 'style') {
        Object.assign(node.style, value);
      } else if (key === 'attr') {
        for (const [name, v] of Object.entries(value)) {
          if (v !== null && v !== undefined && v !== false) {
            node.setAttribute(name, v === true ? '' : String(v));
          }
        }
      } else if (key in node) {
        node[key] = value;
      } else {
        node.setAttribute(key, value === true ? '' : String(value));
      }
    }
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export const text = (value) => document.createTextNode(String(value ?? ''));

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function mount(host, node) {
  clear(host);
  if (node) host.appendChild(node);
  return host;
}

export const fmtTime = (value) =>
  String(value || '').replace('T', ' ').replace('+00:00', 'Z').replace(/\.\d+Z$/, 'Z');

export const shortHash = (value) => (value ? String(value).slice(0, 10) : '\u2014');

export const bytes = (value) => {
  const n = Number(value || 0);
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(1) + ' MB';
};

/** Render a JSON-ish engine value, keeping absent and undecided distinct from
    null and from each other. That distinction is the honesty of the tool. */
export function valueCell(value) {
  if (value === null || value === undefined) {
    return h('span', { class: 'badge', text: 'null' });
  }
  if (typeof value === 'object' && value.$ === 'absent') {
    const node = h('span', { class: 'badge caution', text: 'absent' });
    node.title = 'the field is not in the row at all, which is not the same ' +
      'as null or an empty string';
    return node;
  }
  if (typeof value === 'object' && value.$ === 'undecided') {
    const node = h('span', { class: 'badge', text: 'undecided' });
    node.title = 'this could not be decided from the data given';
    return node;
  }
  if (typeof value === 'object' && value.$ === 'seq') {
    return h('span', { class: 'mono' },
      '[' + value.items.map((item) => valueCell(item).textContent).join(', ') + ']');
  }
  if (typeof value === 'object' && value.$ === 'duration') {
    return h('span', { class: 'mono', text: value.seconds + 's' });
  }
  if (typeof value === 'object') {
    return h('span', { class: 'mono', text: JSON.stringify(value) });
  }
  return h('span', { text: String(value) });
}
