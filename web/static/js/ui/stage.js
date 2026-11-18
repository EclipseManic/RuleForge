/* Editors for every non-Filter stage.

   Each editor mutates the stage in place and redraws only its own body, so the
   rest of the screen keeps its scroll position and focus. Defaults are real
   values, because the IR refuses half-built nodes. */

import { h } from './dom.js';
import { btn, toast } from './components.js';
import { renderCondition } from './condition.js';
import { touch } from '../core/state.js';
import {
  T, MEASURE_FUNCTIONS, describeExpr, fieldRef, fieldRefText, literal,
  literalFromText, literalToText, newComparison,
} from '../core/ir.js';

const input = (props) => h('input', Object.assign({ class: 'input code', type: 'text' }, props));

function numberInput(value, onCommit, props) {
  const node = input(Object.assign({
    value: value === null || value === undefined ? '' : String(value),
    on: {
      change: () => {
        const parsed = parseInt(node.value, 10);
        onCommit(isNaN(parsed) ? null : parsed, node);
        touch();
      },
    },
  }, props || {}));
  return node;
}

function textInput(value, onCommit, props) {
  const node = input(Object.assign({
    value: value || '',
    on: {
      change: () => { onCommit(node.value); touch(); },
    },
  }, props || {}));
  return node;
}

function durationInput(value, onCommit) {
  return textInput(value, onCommit, { placeholder: 'seconds' });
}

function fieldListEditor(host, label, tupleNode) {
  const wrap = h('div', { class: 'stack' });
  wrap.appendChild(h('span', { class: 'field-label', text: label }));
  tupleNode.v.forEach((ref, index) => {
    const row = h('div', { class: 'row' },
      textInput(fieldRefText(ref), (value) => {
        tupleNode.v[index] = fieldRef(value, ref.scope ? ref.scope.v : 'current');
      }, { placeholder: 'FieldName', 'aria-label': label + ' field' }),
      btn('\u00d7', {
        size: 'sm', kind: 'quiet', title: 'remove ' + fieldRefText(ref),
        onClick: () => { tupleNode.v.splice(index, 1); touch(); redraw(host); },
      }));
    wrap.appendChild(row);
  });
  wrap.appendChild(btn('+ field', {
    size: 'sm', kind: 'quiet',
    onClick: () => { tupleNode.v.push(fieldRef('FieldName')); touch(); redraw(host); },
  }));
  host.appendChild(wrap);
}

const redraw = (host) => renderStageBody(host, host._stage);

export function renderStageBody(host, stage) {
  host.textContent = '';
  host._stage = stage;
  const kind = stage['@'];

  if (kind === 'Filter') {
    const slot = h('div');
    renderCondition(slot, stage.condition, (next) => {
      /* A filter whose condition is a bare field matches everything, so the
         last condition cannot be removed into nothing. */
      stage.condition = next || newComparison();
      touch();
      renderStageBody(host, stage);
    }, {});
    host.appendChild(slot);
    return;
  }

  if (kind === 'Aggregate') {
    stage.measures.v.forEach((measure, index) => {
      const row = h('div', { class: 'cond-row' });

      const fn = h('select', { class: 'select', 'aria-label': 'Measure function' });
      for (const name of MEASURE_FUNCTIONS) {
        const option = h('option', { value: name, text: name });
        if (measure.function.v === name) option.selected = true;
        fn.appendChild(option);
      }
      fn.onchange = () => { measure.function = T.str(fn.value); touch(); };
      row.appendChild(fn);

      row.appendChild(textInput(
        measure.field && measure.field['@'] === 'FieldRef' ? fieldRefText(measure.field) : '',
        (value) => { measure.field = value.trim() ? fieldRef(value) : T.nul(); },
        { placeholder: 'field (blank for count)' },
      ));

      row.appendChild(textInput(measure.name.v, (value) => {
        measure.name = T.str(value || 'count');
      }, { placeholder: 'output name' }));

      row.appendChild(h('div', { class: 'cond-actions' },
        btn(measure.distinct.v ? 'distinct' : 'all', {
          size: 'sm', kind: 'quiet', active: measure.distinct.v,
          title: 'distinct de-duplicates values; all does not, and that ' +
            'difference changes an alert',
          onClick: () => {
            measure.distinct = T.bool(!measure.distinct.v);
            touch();
            renderStageBody(host, stage);
          },
        }),
        btn('\u00d7', {
          size: 'sm', kind: 'quiet', title: 'remove this measure',
          onClick: () => {
            if (stage.measures.v.length === 1) {
              toast('a group-by with nothing measured discards every value. ' +
                'Use a Distinct stage if that is what you want.', 'bad');
              return;
            }
            stage.measures.v.splice(index, 1);
            touch();
            renderStageBody(host, stage);
          },
        })));
      host.appendChild(row);
    });

    host.appendChild(btn('+ measure', {
      size: 'sm', kind: 'quiet',
      onClick: () => {
        stage.measures.v.push({
          '@': 'Measure', function: T.str('count'),
          name: T.str('n' + stage.measures.v.length), field: T.nul(),
          distinct: T.bool(false), param: T.nul(),
        });
        touch();
        renderStageBody(host, stage);
      },
    }));

    fieldListEditor(host, 'group by', stage.keys);

    /* window */
    const hasWindow = stage.window && stage.window['@'] === 'Window';
    host.appendChild(btn(hasWindow ? 'remove time window' : '+ time window', {
      size: 'sm', kind: 'quiet',
      onClick: () => {
        stage.window = hasWindow ? T.nul() : {
          '@': 'Window', kind: T.str('tumbling'),
          size: { '@': 'Duration', seconds: T.dec('300') },
          step: T.nul(), time_field: T.str(''), gap: T.nul(),
        };
        touch();
        renderStageBody(host, stage);
      },
    }));

    if (hasWindow) {
      const row = h('div', { class: 'row-3' });
      const kindSelect = h('select', { class: 'select', 'aria-label': 'Window kind' });
      for (const name of ['tumbling', 'sliding', 'cumulative', 'per_event', 'session']) {
        const option = h('option', { value: name, text: name });
        if (stage.window.kind.v === name) option.selected = true;
        kindSelect.appendChild(option);
      }
      kindSelect.onchange = () => {
        const next = kindSelect.value;
        stage.window.kind = T.str(next);
        /* A sliding window needs a step, a session window is defined by its
           gap, and the engine refuses a parameter it would ignore. */
        stage.window.step = next === 'sliding'
          ? { '@': 'Duration', seconds: T.dec('60') } : T.nul();
        stage.window.gap = next === 'session'
          ? { '@': 'Duration', seconds: T.dec('900') } : T.nul();
        if (next === 'sliding' && stage.window.size['@'] === 'null') {
          stage.window.size = { '@': 'Duration', seconds: T.dec('300') };
        }
        touch();
        renderStageBody(host, stage);
      };
      row.appendChild(kindSelect);
      row.appendChild(durationInput(
        stage.window.size['@'] === 'Duration' ? stage.window.size.seconds.v : '',
        (value) => {
          stage.window.size = value.trim()
            ? { '@': 'Duration', seconds: T.dec(value.trim()) } : T.nul();
        },
      ));
      if (stage.window.kind.v === 'sliding') {
        row.appendChild(durationInput(
          stage.window.step['@'] === 'Duration' ? stage.window.step.seconds.v : '',
          (value) => {
            stage.window.step = {
              '@': 'Duration', seconds: T.dec(value.trim() || '60'),
            };
          },
        ));
      }
      if (stage.window.kind.v === 'session') {
        row.appendChild(durationInput(
          stage.window.gap['@'] === 'Duration' ? stage.window.gap.seconds.v : '',
          (value) => {
            stage.window.gap = {
              '@': 'Duration', seconds: T.dec(value.trim() || '900'),
            };
          },
        ));
      }
      host.appendChild(row);
    }
    return;
  }

  if (kind === 'Derive') {
    stage.assignments.v.forEach((pair, index) => {
      const row = h('div', { class: 'cond-row' });
      row.appendChild(textInput(pair.v[0].v, (value) => {
        pair.v[0] = T.str(value);
      }, { placeholder: 'NewColumn' }));
      row.appendChild(h('span', { class: 'muted', text: '=' }));
      row.appendChild(textInput(
        pair.v[1]['@'] === 'Literal' ? literalToText(pair.v[1].value) : describeExpr(pair.v[1]),
        (value) => { pair.v[1] = literal(literalFromText(value)); },
        { placeholder: 'value' },
      ));
      row.appendChild(h('div', { class: 'cond-actions' },
        btn('\u00d7', {
          size: 'sm', kind: 'quiet',
          onClick: () => {
            if (stage.assignments.v.length === 1) {
              toast('a derive stage that computes nothing is refused.', 'bad');
              return;
            }
            stage.assignments.v.splice(index, 1);
            touch();
            renderStageBody(host, stage);
          },
        })));
      host.appendChild(row);
    });
    host.appendChild(btn('+ column', {
      size: 'sm', kind: 'quiet',
      onClick: () => {
        stage.assignments.v.push(T.tuple([T.str('NewColumn'), literal(T.str(''))]));
        touch();
        renderStageBody(host, stage);
      },
    }));
    return;
  }

  if (kind === 'Project') {
    /* keeps and drops are mutually exclusive: a stage that does both is
       ambiguous about what the output is. */
    const keeping = stage.drops.v.length === 0;
    host.appendChild(h('div', { class: 'row' },
      btn(keeping ? 'keeping columns' : 'dropping columns', {
        size: 'sm', kind: 'quiet',
        title: 'switch between a keep-list and a drop-list',
        onClick: () => {
          if (keeping) {
            stage.drops = T.tuple(stage.keeps.v.slice());
            stage.keeps = T.tuple([]);
            stage.renames = T.tuple([]);
          } else {
            stage.keeps = T.tuple(stage.drops.v.slice());
            stage.drops = T.tuple([]);
          }
          touch();
          renderStageBody(host, stage);
        },
      })));

    if (keeping) {
      fieldListEditor(host, 'keep these columns', stage.keeps);
      stage.renames.v.forEach((pair, index) => {
        host.appendChild(h('div', { class: 'row' },
          textInput(fieldRefText(pair.v[0]), (value) => { pair.v[0] = fieldRef(value); },
            { placeholder: 'From' }),
          h('span', { class: 'muted', text: '\u2192' }),
          textInput(pair.v[1].v, (value) => { pair.v[1] = T.str(value); },
            { placeholder: 'To' }),
          btn('\u00d7', {
            size: 'sm', kind: 'quiet',
            onClick: () => {
              stage.renames.v.splice(index, 1);
              touch();
              renderStageBody(host, stage);
            },
          })));
      });
      host.appendChild(btn('+ rename', {
        size: 'sm', kind: 'quiet',
        onClick: () => {
          stage.renames.v.push(T.tuple([fieldRef('Source'), T.str('Target')]));
          touch();
          renderStageBody(host, stage);
        },
      }));
    } else {
      fieldListEditor(host, 'drop these columns', stage.drops);
    }
    return;
  }

  if (kind === 'Sort') {
    stage.keys.v.forEach((pair, index) => {
      host.appendChild(h('div', { class: 'row' },
        textInput(fieldRefText(pair.v[0]), (value) => { pair.v[0] = fieldRef(value); },
          { placeholder: 'FieldName' }),
        btn(pair.v[1].v ? 'descending' : 'ascending', {
          size: 'sm', kind: 'quiet',
          onClick: () => {
            pair.v[1] = T.bool(!pair.v[1].v);
            touch();
            renderStageBody(host, stage);
          },
        }),
        btn('\u00d7', {
          size: 'sm', kind: 'quiet',
          onClick: () => {
            stage.keys.v.splice(index, 1);
            touch();
            renderStageBody(host, stage);
          },
        })));
    });
    host.appendChild(btn('+ sort key', {
      size: 'sm', kind: 'quiet',
      onClick: () => {
        stage.keys.v.push(T.tuple([fieldRef('FieldName'), T.bool(true)]));
        touch();
        renderStageBody(host, stage);
      },
    }));
    return;
  }

  if (kind === 'Limit') {
    host.appendChild(h('div', { class: 'row' },
      numberInput(stage.count.v, (parsed) => {
        stage.count = T.int(parsed === null ? 100 : parsed);
      }, { placeholder: 'rows' }),
      btn(stage.keep_last.v ? 'last rows' : 'first rows', {
        size: 'sm', kind: 'quiet',
        onClick: () => {
          stage.keep_last = T.bool(!stage.keep_last.v);
          touch();
          renderStageBody(host, stage);
        },
      })));
    return;
  }

  if (kind === 'Distinct') {
    fieldListEditor(host, 'distinct on', stage.keys);
    return;
  }

  if (kind === 'Expand') {
    host.appendChild(h('div', { class: 'row' },
      textInput(fieldRefText(stage.field), (value) => { stage.field = fieldRef(value); },
        { placeholder: 'list field' }),
      h('span', { class: 'muted', text: '\u2192' }),
      textInput(stage.into.v, (value) => { stage.into = T.str(value); },
        { placeholder: 'into (optional)' })));
    return;
  }

  if (kind === 'Correlation') {
    host.appendChild(h('div', { class: 'row-3' },
      textInput(stage.parent.v, (value) => { stage.parent = T.str(value); },
        { placeholder: 'parent stage or binding' }),
      numberInput(stage.frequency.v, (parsed) => {
        stage.frequency = T.int(parsed === null || parsed < 1 ? 1 : parsed);
      }, { placeholder: 'times' }),
      durationInput(stage.timeframe.seconds.v, (value) => {
        stage.timeframe = { '@': 'Duration', seconds: T.dec(value.trim() || '300') };
      })));
    host.appendChild(h('p', {
      class: 'field-hint',
      text: 'The count is the predicate: the rule fires when the parent matches ' +
        'this many times inside the timeframe, per group.',
    }));
    fieldListEditor(host, 'grouped on', stage.group_by);
    return;
  }

  if (kind === 'Sequence') {
    /* The ORDER is the point: procdump then lsass is credential dumping, the
       reverse is not. Steps are numbered and cannot be reordered. */
    host.appendChild(h('div', { class: 'row' },
      durationInput(
        stage.maxspan['@'] === 'Duration' ? stage.maxspan.seconds.v : '',
        (value) => {
          const trimmed = value.trim();
          /* Unbounded is a real choice and a dangerous one, so it is allowed
             and stated rather than defaulted. */
          stage.maxspan = trimmed
            ? { '@': 'Duration', seconds: T.dec(trimmed) } : T.nul();
        },
      ),
      h('span', {
        class: 'field-hint',
        text: 'window from the first step to the last',
      })));

    fieldListEditor(host, 'the steps must agree on', stage.by);

    stage.steps.v.forEach((step, index) => {
      const box = h('div', { class: 'cond-group' });
      const label = h('div', { class: 'row' },
        h('span', { class: 'stage-id', text: 'step ' + (index + 1) }),
        numberInput(step.runs.v, (parsed) => {
          step.runs = T.int(parsed === null || parsed < 1 ? 1 : parsed);
        }, { placeholder: 'repeats' }));
      if (stage.steps.v.length > 2) {
        label.appendChild(btn('remove', {
          size: 'sm', kind: 'quiet',
          onClick: () => {
            stage.steps.v.splice(index, 1);
            touch();
            renderStageBody(host, stage);
          },
        }));
      }
      box.appendChild(label);
      const slot = h('div');
      renderCondition(slot, step.condition, (next) => {
        step.condition = next || newComparison();
        touch();
      }, {});
      box.appendChild(slot);
      host.appendChild(box);
    });

    host.appendChild(btn('add a step', {
      size: 'sm', kind: 'quiet',
      onClick: () => {
        stage.steps.v.push({
          '@': 'SequenceStep', condition: newComparison(), runs: T.int(1),
        });
        touch();
        renderStageBody(host, stage);
      },
    }));

    const hasUntil = stage.until && stage.until['@'] !== 'null';
    host.appendChild(btn(hasUntil ? 'remove the cancellation' : 'add a cancellation', {
      size: 'sm', kind: 'quiet',
      title: 'a cancelled chain is not a detection',
      onClick: () => {
        stage.until = hasUntil ? T.nul() : newComparison();
        touch();
        renderStageBody(host, stage);
      },
    }));
    if (hasUntil) {
      host.appendChild(h('p', {
        class: 'field-hint',
        text: 'When this matches, any partial sequence for the key is abandoned.',
      }));
      const slot = h('div');
      renderCondition(slot, stage.until, (next) => {
        stage.until = next || newComparison();
        touch();
      }, {});
      host.appendChild(slot);
    }
    return;
  }

  if (kind === 'Emit') {
    fieldListEditor(host, 'columns to output (blank for all)', stage.keeps);
    fieldListEditor(host, 'de-duplicate alerts on', stage.dedupe_by);
    return;
  }

  /* No editor for this kind: stated rather than shown as an empty panel. */
  host.appendChild(h('div', { class: 'cond-readonly', text: describeExpr(stage) }));
  host.appendChild(h('p', {
    class: 'field-hint',
    text: 'This builder has no editor for a ' + kind + ' stage yet, so it is ' +
      'shown read-only. It is preserved exactly as it was imported.',
  }));
}
