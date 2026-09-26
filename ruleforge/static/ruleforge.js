/* RuleForge workshop.
 *
 * EVERYTHING THAT COMES FROM A RULE GOES IN THROUGH textContent.
 *
 * The rule text is the analyst's own, but it is also attacker-reachable: a rule
 * pasted from a shared document, a SIEM rule export, or a ticket can contain
 * anything, including markup. Assigning a rule to a node's HTML content would
 * execute it. So this file never assigns HTML from a string -- the only
 * assignments are to className and textContent, both of which are inert. There
 * is a test that greps this file for the forbidden APIs and fails if one appears.
 */
"use strict";

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/* --- tabs ---------------------------------------------------------------- */
$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    $$(".tab").forEach((t) => t.classList.remove("active"));
    $$(".tabpanel").forEach((p) => p.classList.add("hidden"));
    tab.classList.add("active");
    const panel = $(`.tabpanel[data-panel="${tab.dataset.tab}"]`);
    if (panel) panel.classList.remove("hidden");
  });
});

/* --- rendering the answer ------------------------------------------------ */
function renderFindings(target, findings, refusal) {
  clear(target);

  if (refusal) {
    const box = el("div", "refusal");
    box.appendChild(el("strong", null, refusal.code));
    box.appendChild(el("p", null, refusal.message));
    target.appendChild(box);
    return;
  }

  if (!findings || findings.length === 0) {
    target.appendChild(el("p", "note", "Nothing flagged."));
    return;
  }

  const order = { problem: 0, caution: 1, note: 2 };
  const sorted = findings.slice().sort(
    (a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3)
  );

  sorted.forEach((f) => {
    const item = el("div", `finding ${f.severity || "note"}`);
    item.appendChild(el("code", null, f.code));
    item.appendChild(el("p", null, f.message));

    /* Show the difference between CHECKED and merely READ. A finding with no
     * evidence is a reading of the rule, not a result, and the analyst should
     * not have to guess which they are looking at. */
    const tag = el("span", f.verified ? "verified" : "unverified",
      f.verified ? "checked" : "read from the text");
    item.appendChild(tag);
    if (f.evidence) {
      item.appendChild(el("small", "evidence", `against: ${f.evidence}`));
    }
    target.appendChild(item);
  });
}

function renderGraph(target, data) {
  clear(target);
  if (!data) return;

  if (data.nodes) {
    const list = el("ol", "nodes");
    data.nodes.forEach((n) => {
      const item = el("li");
      item.appendChild(el("code", null, n.kind));
      item.appendChild(el("span", "nid", ` ${n.id}`));
      if (n.input) item.appendChild(el("small", "edge", ` ← ${n.input}`));
      if (n.kind === "Aggregate" && n.measures) {
        item.appendChild(
          el("small", "measures",
            n.measures.map((m) => `${m.name}=${m.function}(${m.field || "*"})`)
              .join(", "))
        );
      }
      if (n.kind === "Package") {
        item.appendChild(
          el("small", "measures",
            `counts ${n.count_subject} ×${n.frequency} / ` +
            `${n.timeframe}s on ${(n.same_fields || []).join(", ")}`)
        );
      }
      list.appendChild(item);
    });
    target.appendChild(list);
    return;
  }

  /* the log -> rule field table */
  if (data.fields) {
    const table = el("table");
    const head = el("tr");
    ["field", "present", "absent", "distinct", "values"].forEach((h) =>
      head.appendChild(el("th", null, h))
    );
    table.appendChild(head);
    data.fields.forEach((f) => {
      const row = el("tr");
      row.appendChild(el("td", null, f.field));
      row.appendChild(el("td", null, f.present));
      row.appendChild(el("td", null, f.absent));
      row.appendChild(el("td", null, f.distinct));
      row.appendChild(el("td", null, f.values.join(", ")));
      table.appendChild(row);
    });
    target.appendChild(table);
  }

  if (data.verdict) {
    const box = el("div", `verdict ${data.verdict}`);
    box.appendChild(el("strong", null, data.verdict));
    if (data.rows !== undefined) {
      box.appendChild(el("span", null, ` ${data.rows} rows`));
    }
    if (data.reason) {
      box.appendChild(el("small", "evidence", ` ${data.reason_detail || data.reason}`));
    }
    target.appendChild(box);
    if (data.trace && data.trace.length) {
      const trace = el("ol", "trace");
      data.trace.forEach((t) =>
        trace.appendChild(
          el("li", null, `${t.node}: ${t.in} → ${t.out}`)
        )
      );
      target.appendChild(trace);
    }
  }
}

/* --- the four calls ------------------------------------------------------ */
function panelFor(button) {
  return button.closest(".tabpanel");
}

function collect(panel, job) {
  const dialect = $(`#${job[0]}-dialect`, panel);
  const rule = $(`#${job[0]}-rule`, panel);
  const body = {
    dialect: dialect ? dialect.value : "",
    rule: rule ? rule.value : "",
    rule_id: "rule",
    save: false,
  };
  const idBox = $(`#${job[0]}-id`, panel);
  if (idBox) body.rule_id = idBox.value;

  const save = $(`#${job[0]}-save`, panel);
  if (save) body.save = save.checked;

  const events = $(`#${job[0]}-events`, panel);
  if (events) body.events = events.value;
  return body;
}

async function call(job, body, panel) {
  const out = panel.querySelector(".out") || panel;
  const findings = out.querySelector(".findings");
  const rendered = out.querySelector(".rendered");
  const graph = out.querySelector(".graph");

  clear(findings);
  findings.appendChild(el("p", "note", "Working…"));

  let data;
  try {
    const response = await fetch(`/api/${job}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    /* A 500 HAS TO BECOME A MESSAGE. Without the `ok` check, `response.json()`
     * throws inside the promise, the rejection is never caught, and the panel
     * sits on "Working…" FOREVER -- which is what a real bug did: `tune` 500'd on
     * the ordinary case of a rule whose fields the sample lacks, and the analyst
     * was left staring at a spinner. */
    if (!response.ok) {
      renderFindings(findings, [], {
        code: `HTTP_${response.status}`,
        message: "The server failed to answer. This is a bug in RuleForge, not " +
                 "something wrong with your rule. The detail is in the " +
                 "terminal running it.",
      });
      return;
    }
    data = await response.json();
  } catch (error) {
    renderFindings(findings, [], {
      code: "REQUEST_FAILED",
      message: `Could not reach RuleForge: ${error}. Is the server still ` +
               `running?`,
    });
    return;
  }

  renderFindings(findings, data.findings, data.refusal);
  if (rendered) {
    rendered.textContent = data.rendered || "(not written back)";
  }
  renderGraph(graph, data.result || data.graph);

  if (data.saved) {
    findings.appendChild(el("p", "note", "Saved to History."));
    /* The cap is the one place history loses anything, so it is said out loud
     * rather than left for the user to assume nothing went. */
    if (data.dropped) {
      findings.appendChild(
        el("p", "note",
          `${data.dropped} older ${data.dropped === 1 ? "entry was" : "entries were"} ` +
          `dropped to stay under the ${2000}-entry cap.`)
      );
    }
  }
}

$$(".go").forEach((button) => {
  button.addEventListener("click", () => {
    const panel = panelFor(button);
    const job = button.dataset.job;
    const prefix = job.startsWith("debug_") ? "d" : job[0];
    const body = {
      dialect: $(`#${prefix}-dialect`, panel).value,
      rule: $(`#${prefix}-rule`, panel).value,
      rule_id: "rule",
      save: false,
      events: $(`#${prefix}-events`, panel)
        ? $(`#${prefix}-events`, panel).value
        : "",
    };
    call(job, body, panel);
  });
});
