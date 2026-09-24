const patternDefaults = (() => { try { const raw = JSON.parse(document.querySelector('#technique-data').textContent || '{}'); const out = {}; for (const [id, t] of Object.entries(raw)) out[id] = {field: t.field || '', value: t.value || '', description: t.description || ''}; if (!out.custom) out.custom = {field: 'process.name', value: 'example.exe', description: ''}; return out; } catch { return {custom: {field: 'process.name', value: 'example.exe', description: ''}}; } })();
const VIEW_META = {
  compose:   ['Compose a detection', 'Describe the behaviour once. Get a reviewable, vendor-native rule for every target you run.'],
  import:    ['Import a rule or event', 'Paste something you already have. The analyser extracts the predicates so you edit instead of retyping.'],
  test:      ['Test against sample events', 'Evaluate the rule clause by clause against real events, locally. Nothing is deployed.'],
  attack:    ['MITRE ATT&CK reference', 'Browse the catalog and jump straight into a buildable pattern.'],
  coverage:  ['Measured coverage', 'Every pattern compiled against every target and structurally parsed. Fidelity is measured, not claimed.'],
  mappings:  ['Field mappings', 'Pin your own field names, and see where each built-in mapping came from.'],
  history:   ['Rule history', 'Everything you generated or analysed, kept locally so you can revisit it.'],
};

const primaryTabs = [...document.querySelectorAll('.primary-tab')];
const subTabs = [...document.querySelectorAll('.sub-tab')];
const subPanels = document.querySelectorAll('.view');
const shells = document.querySelectorAll('.shell');
const subbar = document.querySelector('#subbar');
/* Declared with the other nav state, not beside loadHome: showPrimary() calls loadHome()
   during init, so a later `let` would be in its temporal dead zone and throw. */
let homeLoading = false;
function announce(message) { const region = document.querySelector('#status'); if (region) region.textContent = message; }
function storeKey(key, value) { try { localStorage.setItem(`ruleforge.${key}`, value); } catch {} }
function readKey(key) { try { return localStorage.getItem(`ruleforge.${key}`); } catch { return null; } }

function showSubTab(id, focusTab) {
  if (!subTabs.some(t => t.dataset.tab === id)) id = 'compose';
  subTabs.forEach(t => { const active = t.dataset.tab === id; t.classList.toggle('active', active); t.setAttribute('aria-selected', active ? 'true' : 'false'); t.tabIndex = active ? 0 : -1; if (active && focusTab) t.focus(); });
  subPanels.forEach(p => { const active = p.id === `view-${id}`; p.classList.toggle('active', active); p.hidden = !active; });
  const meta = VIEW_META[id] || [];
  const title = document.querySelector('#view-title');
  const sub = document.querySelector('#view-sub');
  if (title && meta[0]) title.textContent = meta[0];
  if (sub && meta[1]) sub.textContent = meta[1];
  storeKey('activeTab', id);
  if (id === 'attack') loadAttack();
  if (id === 'coverage') loadCoverage();
  if (id === 'mappings') loadMappings();
  if (id === 'history') loadHistory();
}

function showPrimary(id, focusTab) {
  if (!primaryTabs.some(t => t.dataset.primary === id)) id = 'home';
  primaryTabs.forEach(t => { const active = t.dataset.primary === id; t.classList.toggle('active', active); t.setAttribute('aria-selected', active ? 'true' : 'false'); t.tabIndex = active ? 0 : -1; if (active && focusTab) t.focus(); });
  shells.forEach(s => s.classList.toggle('active', s.id === `view-${id}`));
  if (subbar) subbar.classList.toggle('on', id === 'studio');
  storeKey('primary', id);
  if (id === 'home') loadHome();
}

function showTab(id) { showPrimary('studio'); showSubTab(id); }

function wireRovingTablist(container, onActivate) { if (!container || container.dataset.wired) return; container.dataset.wired = 'true'; const items = () => [...container.querySelectorAll('[role="tab"]')]; container.addEventListener('keydown', event => { const list = items(); const current = list.indexOf(document.activeElement); if (current < 0) return; let next = null; if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (current + 1) % list.length; else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (current - 1 + list.length) % list.length; else if (event.key === 'Home') next = 0; else if (event.key === 'End') next = list.length - 1; if (next !== null) { event.preventDefault(); list[next].focus(); onActivate(list[next]); } }); }
primaryTabs.forEach(tab => tab.addEventListener('click', () => showPrimary(tab.dataset.primary)));
subTabs.forEach(tab => tab.addEventListener('click', () => showSubTab(tab.dataset.tab)));
wireRovingTablist(document.querySelector('#primary-tabs'), tab => showPrimary(tab.dataset.primary));
wireRovingTablist(document.querySelector('#sub-tabs'), tab => showSubTab(tab.dataset.tab));
document.querySelectorAll('[data-jump]').forEach(button => button.addEventListener('click', () => showTab(button.dataset.jump)));
const savedPrimary = readKey('primary');
const savedSub = readKey('activeTab');
showPrimary(primaryTabs.some(t => t.dataset.primary === savedPrimary) ? savedPrimary : 'home');
showSubTab(subTabs.some(t => t.dataset.tab === savedSub) ? savedSub : 'compose');

/* Theme: the people using this live in consoles all day, so dark is the default. */
const themeToggle = document.querySelector('#theme-toggle');
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem('ruleforge.theme', theme); } catch {}
  if (themeToggle) {
    const next = theme === 'dark' ? 'light' : 'dark';
    themeToggle.setAttribute('aria-label', `Switch to ${next} theme`);
  }
}
if (themeToggle) {
  themeToggle.addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  let stored = null;
  try { stored = localStorage.getItem('ruleforge.theme'); } catch {}
  applyTheme(stored || 'dark');
}

const technique = document.querySelector('#technique');
function addCondition(target, values = {}) { const row = document.createElement('div'); row.className = 'condition-row'; row.innerHTML = `<input data-condition-field list="field-names" aria-label="Match field" value="${escapeHtml(values.field || '')}" placeholder="Field name" required><select data-condition-operator aria-label="Match operator"><option value="contains">Contains</option><option value="equals">Equals</option><option value="starts_with">Starts with</option><option value="ends_with">Ends with</option><option value="regex">Regex</option><option value="in_list">In list</option><option value="wildcard">Wildcard</option><option value="windash">Windash -//</option><option value="base64">Base64</option><option value="exists">Exists</option><option value="cidr">CIDR range</option></select><input data-condition-value aria-label="Match value" value="${escapeHtml(values.value || '')}" placeholder="Value" required><button type="button" class="remove-condition" aria-label="Remove condition">×</button>`; target.appendChild(row); row.querySelector('[data-condition-operator]').value = values.operator || 'contains'; const remove = row.querySelector('.remove-condition'); remove.addEventListener('click', () => { if (target.children.length > 1 || target.id === 'exclusion-list') { row.remove(); syncRemoveButtons(); } }); syncRemoveButtons(); }
function syncRemoveButtons() { document.querySelectorAll('#condition-list .condition-row .remove-condition').forEach(button => { const locked = document.querySelectorAll('#condition-list .condition-row').length <= 1; button.disabled = locked; button.title = locked ? 'At least one condition is required' : 'Remove condition'; }); }
const conditionList = document.querySelector('#condition-list'); const exclusionList = document.querySelector('#exclusion-list');
addCondition(conditionList, patternDefaults.encoded_powershell); document.querySelector('#add-condition').addEventListener('click', () => addCondition(conditionList)); document.querySelector('#add-exclusion').addEventListener('click', () => addCondition(exclusionList));
function addStage(target, values = {}) { const row = document.createElement('div'); row.className = 'condition-row'; row.innerHTML = `<input data-stage-event aria-label="Stage event" value="${escapeHtml(values.event || '')}" placeholder="Event, e.g. logon"><input data-stage-condition aria-label="Stage condition (EQL where-clause, blank reuses logic)" value="${escapeHtml(values.condition || '')}" placeholder="where-clause, blank = reuse logic"><label class="negated-check"><input type="checkbox" data-stage-negated${values.negated ? ' checked' : ''}> Negated</label><button type="button" class="remove-condition" aria-label="Remove stage">×</button>`; target.appendChild(row); row.querySelector('.remove-condition').addEventListener('click', () => row.remove()); }
const stageList = document.querySelector('#stage-list'); document.querySelector('#add-stage').addEventListener('click', () => addStage(stageList));
const correlationType = document.querySelector('#correlation-type');
function syncCorrelationEditors() { const t = correlationType.value; document.querySelector('#sequence-editor').hidden = t !== 'sequence'; document.querySelector('#join-editor').hidden = t !== 'join'; document.querySelector('#aggregation-editor').hidden = t !== 'aggregation'; if (t === 'sequence' && !stageList.children.length) { addStage(stageList); addStage(stageList); } }
correlationType.addEventListener('change', syncCorrelationEditors); syncCorrelationEditors();
function currentCorrelation() { const t = correlationType.value; if (t === 'sequence') { const stages = [...stageList.querySelectorAll('.condition-row')].map(row => ({event: row.querySelector('[data-stage-event]').value, condition: row.querySelector('[data-stage-condition]').value, negated: row.querySelector('[data-stage-negated]').checked})).filter(s => s.event.trim() || s.condition.trim()); if (!stages.length) return {}; return {sequences: [{join_by: document.querySelector('#sequence-join-by').value, maxspan: document.querySelector('#sequence-maxspan').value, stages}]}; } if (t === 'join') { const join = {kind: document.querySelector('#join-kind').value, left: document.querySelector('#join-left').value, right: document.querySelector('#join-right').value, on: document.querySelector('#join-on').value}; if (!join.left.trim() && !join.right.trim() && !join.on.trim()) return {}; return {joins: [join]}; } if (t === 'aggregation') { const agg = {function: document.querySelector('#agg-function').value, field: document.querySelector('#agg-field').value, alias: document.querySelector('#agg-alias').value}; return {aggregations: [agg]}; } return {}; }
technique.addEventListener('change', () => {
  const d = patternDefaults[technique.value] || patternDefaults.custom;
  /* Rebuild rather than patch the first row. Patching left any extra condition the
     analyst had added in place, so the field/value below changed underneath it and the
     result mixed two unrelated behaviours. */
  conditionList.replaceChildren();
  addCondition(conditionList, { field: d.field, value: d.value, operator: 'contains' });
  document.querySelector('#f-description').value = d.description;
});
const targetToggle = document.querySelector('#toggle-targets');
targetToggle.addEventListener('click', () => { const boxes = [...document.querySelectorAll('[name="siems"]')]; const allChecked = boxes.every(box => box.checked); boxes.forEach(box => box.checked = !allChecked); targetToggle.textContent = allChecked ? 'Select all' : 'Clear all'; const count = boxes.filter(box => box.checked).length; announce(`${count} of ${boxes.length} SIEM targets selected.`); });
const thresholdToggle = document.querySelector('#use-threshold');
function syncThresholdControls() { const enabled = thresholdToggle.checked; document.querySelector('#threshold').disabled = !enabled; document.querySelector('[name="group_by"]').disabled = !enabled; document.querySelector('#thr-minus').disabled = !enabled; document.querySelector('#thr-plus').disabled = !enabled; syncThrValue(); }
thresholdToggle.addEventListener('change', syncThresholdControls); syncThresholdControls();
document.querySelector('#import-rule').addEventListener('input', () => { if (importedSource) { importedSourceDirty = true; importedCompileBlocked = true; const compileButton = document.querySelector('#rule-form button[type=submit]'); if (compileButton) compileButton.disabled = true; } });

document.querySelector('#analyze-rule').addEventListener('click', async () => {
  const button = document.querySelector('#analyze-rule');
  const resultBox = document.querySelector('#analysis-result');
  const rule = document.querySelector('#import-rule').value.trim();
  if (!rule) { resultBox.textContent = 'Paste a rule to analyze.'; return; }
  button.disabled = true; button.innerHTML = '<span>Analyzing…</span><span class="spinner"></span>'; resultBox.textContent = '';
  try {
    const response = await fetch('/api/analyze', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({rule, siem: document.querySelector('#import-siem').value})});
    const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Unable to analyze rule.');
    if (!body || !Array.isArray(body.conditions) || !body.payload_defaults || typeof body.payload_defaults !== 'object' || !Array.isArray(body.suggestions)) throw new Error('Unexpected analysis response.');
    const defaults = body.payload_defaults;
    conditionList.replaceChildren();
    body.conditions.forEach(condition => addCondition(conditionList, condition));
    if (!body.conditions.length) addCondition(conditionList, body.payload_defaults);
    document.querySelector('#condition-logic').value = 'all';
    technique.value = 'custom';
    document.querySelector('[name="title"]').value = `Imported ${body.detected_siem} rule`;
    document.querySelector('#f-description').value = `Imported ${body.detected_siem} rule for analyst review and tuning.`;
    document.querySelectorAll('[name="siems"]').forEach(box => { box.checked = box.value === body.siem; });
    document.querySelector('#toggle-targets').textContent = 'Select all';
    thresholdToggle.checked = body.payload_defaults.use_threshold;
    document.querySelector('[name="data_source"]').value = body.payload_defaults.data_source;
    document.querySelector('[name="group_by"]').value = body.payload_defaults.group_by;
    syncThresholdControls();
    document.querySelector('[name="threshold"]').value = defaults.threshold;
    document.querySelector('[name="timeframe"]').value = defaults.timeframe;
    importedSource = {rule, siem: body.siem};
    importedSourceDirty = false;
    importedAnalysis = body;
    importedCompileBlocked = false;
    const compileButton = document.querySelector('#rule-form button[type=submit]');
    if (compileButton) compileButton.disabled = false;
    const modelItems = [
      ...(body.event_streams || []).map(stream => `Event stream: ${stream.name} -> ${stream.source}`),
      ...(body.joins || []).map(join => `Join: ${join.kind} ${join.right} on ${join.on}`),
      ...(body.sequences || []).map(sequence => `Sequence: ${sequence.stages.length} stage(s), by ${sequence.join_by}, maxspan ${sequence.maxspan}`),
      ...(body.time_constraints || []).map(constraint => `Time constraint: ${constraint}`),
      ...(body.aggregations || []).map(aggregation => `Aggregation: ${aggregation.function}(${aggregation.field || '*'})${aggregation.alias ? ` as ${aggregation.alias}` : ''}`),
      ...(body.lookups || []).map(lookup => `Lookup: ${lookup.name}`),
    ];
    const modelBox = document.querySelector('#imported-model');
    modelBox.hidden = modelItems.length === 0;
    const streamFields = (body.event_streams || []).map(stream => `<div class="model-row"><label>Event name<input data-model-stream-name value="${escapeHtml(stream.name)}"></label><label>Source/table<input data-model-stream-source value="${escapeHtml(stream.source)}"></label></div>`).join('');
    const joinFields = (body.joins || []).map(join => `<div class="model-row"><label>Join type<input data-model-join-kind value="${escapeHtml(join.kind)}"></label><label>Right stream<input data-model-join-right value="${escapeHtml(join.right)}"></label><label>Join key<input data-model-join-on value="${escapeHtml(join.on)}"></label></div>`).join('');
    const timeFields = (body.time_constraints || []).map(constraint => `<label>Time relationship<input data-model-time value="${escapeHtml(constraint)}"></label>`).join('');
    modelBox.innerHTML = modelItems.length ? `<strong>Advanced correlation model · section 02</strong>${streamFields}${joinFields}${timeFields}<ul>${modelItems.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul><small>${body.equivalent_recompile ? 'These fields can be tuned and recompiled.' : 'These fields are the analyzed wiring. The pasted box is only the import reference; sections 1–3 are the analyst workspace.'}</small>` : '';
    const preserved = [...(body.sequences || []).map(item => `Sequence: ${item.stages.length} stage(s), joined by ${item.join_by}`), ...(body.joins || []).map(item => `Join: ${item.kind} on ${item.on}`), ...(body.lookups || []).map(item => `Lookup: ${item.name}`), ...(body.aggregations || []).map(item => `Aggregation: ${item.function}(${item.field || '*'})`), ...Object.keys(body.native_sections || {}).map(section => `Native section: ${section}`)];
    const sectionHtml = (body.section_blocks || []).map((block, bi) => `<details class="section-block"${bi === 0 ? ' open' : ''}><summary>${escapeHtml(block.title)}</summary><pre><code>${escapeHtml(block.code)}</code></pre></details>`).join('');
    const expl = body.explanation || {};
    const explCards = expl.bullets ? `<div class="explainer-grid"><div class="explainer-card"><h4>Summary</h4><p>${escapeHtml(expl.summary || '')}</p></div>${(expl.lossy_flags || []).length ? `<div class="explainer-card flags"><h4>Review flags</h4><ul>${expl.lossy_flags.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul></div>` : ''}</div>` : '';
    resultBox.innerHTML = `<strong>${escapeHtml(body.detected_siem)} detected · ${escapeHtml(body.detection_confidence)} confidence</strong><span class="fidelity-badge ${escapeHtml(body.fidelity)}">${escapeHtml(body.fidelity)} recompile</span>${body.faithfulness ? `<span class="fidelity-badge ${body.faithfulness.badge === 'faithful' ? 'exact' : 'partial'}" title="${escapeHtml((body.faithfulness.reasons || []).join('; '))}">round-trip ${escapeHtml(body.faithfulness.badge)}</span>` : ''}<p>${escapeHtml(body.detection_reason)}</p>${explCards}${sectionHtml}<p>${body.mode === 'simple' ? 'Simple rule recognized' : 'Advanced logic detected'}${body.conditions.length ? `<br>${body.conditions.map(condition => `${escapeHtml(condition.field)} ${escapeHtml(condition.operator)} <code>${escapeHtml(condition.value)}</code>`).join('<br>')}` : '<br>No simple field comparison was recognized.'}</p>${preserved.length ? `<p><b>Preserved native structure</b><br>${preserved.map(item => escapeHtml(item)).join('<br>')}</p>` : ''}<ul>${body.suggestions.map(suggestion => `<li>${escapeHtml(suggestion)}</li>`).join('')}</ul>`; loadHistory();
  } catch (error) { resultBox.innerHTML = `<div role="alert">Error: ${escapeHtml(error.message)}</div>`; }
  finally { button.disabled = false; button.innerHTML = 'Analyze and configure <span>↗</span>'; }
});
let validateTimer = null;
document.querySelector('#import-rule').addEventListener('input', () => {
  clearTimeout(validateTimer);
  validateTimer = setTimeout(async () => {
    const box = document.querySelector('#import-validation');
    const text = document.querySelector('#import-rule').value.trim();
    if (!text.includes(':') || text.length < 20) { box.innerHTML = ''; return; }
    try {
      const response = await fetch('/api/validate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({sigma: text})});
      const body = await response.json();
      if (!response.ok || body.valid) { box.innerHTML = body.valid ? '<span class="finding-ok">✓ Sigma structure looks valid.</span>' : ''; return; }
      const findings = (body.findings || []).slice(0, 6);
      box.innerHTML = `<strong>Live check:</strong><ul>${findings.map(f => `<li class="finding-${escapeHtml(String(f.severity || 'LOW').toLowerCase())}">${f.kind && f.kind !== 'finding' ? `<em>[${escapeHtml(f.kind)}]</em> ` : ''}[${escapeHtml(String(f.severity || 'LOW'))}] ${escapeHtml(f.message || '')}</li>`).join('')}</ul>`;
    } catch { box.innerHTML = ''; }
  }, 600);
});

let compiledRules = [];
let currentPayload = null;
let currentQualityGates = [];
let currentCompileContract = null;
let importedSource = null;
let importedSourceDirty = false;
let importedAnalysis = null;
let importedCompileBlocked = false;
const form = document.querySelector('#rule-form');
const errorBox = document.querySelector('#form-error');
/* The error box ships with the `hidden` attribute. Without these the submit handler
   filled it with text that the analyst never saw, because nothing cleared `hidden`. */
function showError(message) { errorBox.textContent = message; errorBox.hidden = false; errorBox.setAttribute('role', 'alert'); }
function clearError() { errorBox.textContent = ''; errorBox.hidden = true; }
form.addEventListener('input', () => { if (importedSource) importedSourceDirty = true; });
form.addEventListener('submit', async event => {
    event.preventDefault(); clearError(); const submit = form.querySelector('button[type=submit]');
  if (importedCompileBlocked) { showError('This advanced rule contains native correlation logic. Edit and re-analyze the source rule instead of compiling the flattened condition view.'); return; }
  /* The threshold stepper lives in the Test panel, OUTSIDE #rule-form, so FormData never
     captured it and the compiled rule silently used the backend default of 1. The Test tab
     reads the same control via currentFormConditions(), so the two disagreed. An invalid
     typed value is rejected here rather than silently clamped, because reportValidity()
     cannot validate a control outside the form. */
  const thresholdState = readThreshold();
  if (thresholdState.error) { showError(thresholdState.error); return; }
  const thresholdValue = thresholdState.value;
  const data = Object.fromEntries(new FormData(form).entries()); data.threshold = thresholdValue; data.use_threshold = thresholdToggle.checked; data.strict = document.querySelector('#strict').checked; data.siems = [...document.querySelectorAll('[name="siems"]:checked')].map(node => node.value); data.conditions = [...conditionList.querySelectorAll('.condition-row')].map(row => ({field: row.querySelector('[data-condition-field]').value, operator: row.querySelector('[data-condition-operator]').value, value: row.querySelector('[data-condition-value]').value})); if (!data.conditions.length || !data.conditions[0].field) { showError('Add at least one detection condition with a field name.'); return; } if (!patternDefaults[data.technique]) { showError('Choose a behavior pattern from the list.'); return; } data.exclude_conditions = [...exclusionList.querySelectorAll('.condition-row')].map(row => ({field: row.querySelector('[data-condition-field]').value, operator: row.querySelector('[data-condition-operator]').value, value: row.querySelector('[data-condition-value]').value})); data.correlation = currentCorrelation(); data.correlation_model = {streams: [...document.querySelectorAll('[data-model-stream-name]')].map((node, index) => ({name: node.value, source: document.querySelectorAll('[data-model-stream-source]')[index]?.value || ''})), joins: [...document.querySelectorAll('[data-model-join-on]')].map((node, index) => ({kind: document.querySelectorAll('[data-model-join-kind]')[index]?.value || 'inner', right: document.querySelectorAll('[data-model-join-right]')[index]?.value || '', on: node.value})), time_constraints: [...document.querySelectorAll('[data-model-time]')].map(node => node.value)}; data.field = data.conditions[0].field; data.operator = data.conditions[0].operator; data.value = data.conditions[0].value; if (importedSource) { data.source_rule = importedSource.rule; data.source_siem = importedSource.siem; data.source_analysis = importedAnalysis; data.preserve_source_rule = !importedSourceDirty; }
  if (!form.reportValidity()) return;
  submit.disabled = true; submit.innerHTML = '<span>Compiling templates…</span><span class="spinner"></span>';
  try { const response = await fetch('/api/generate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)}); const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Unable to generate templates.'); currentPayload = data; compiledRules = body.rules; currentQualityGates = body.quality_gates || []; currentCompileContract = body.compile_contract || null; renderRules(compiledRules, currentQualityGates); loadHistory();
    try { const expResp = await fetch('/api/explain', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...currentFormConditions(), rule: undefined})}); const exp = await expResp.json(); if (expResp.ok && exp.bullets) renderExplainerCards(exp); } catch {}
    try { const cmpResp = await fetch('/api/compile', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...currentFormConditions(), title: data.title, siems: data.siems})}); const cmp = await cmpResp.json(); if (cmpResp.ok && cmp.model) lastCompiledModel = cmp.model; } catch {}
  }
  catch (error) { showError(error.message); }
  finally { submit.disabled = false; submit.innerHTML = '<span>Compile rule templates</span><span>→</span>'; }
});

function escapeHtml(string) { return String(string).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[char])); }
let activeSiemTab = 0;
function renderRules(rules, gates) { const output = document.querySelector('#results'); const list = document.querySelector('#result-list'); const gateList = document.querySelector('#quality-gates'); const tabBar = document.querySelector('#siem-tabs'); const outputCount = document.querySelector('#output-count'); const outputEmpty = document.querySelector('#output-empty'); if (outputCount) outputCount.textContent = rules.length + (rules.length === 1 ? ' target' : ' targets'); if (outputEmpty) outputEmpty.hidden = true; document.querySelectorAll('#download-all, #run-evasion').forEach(button => { button.disabled = rules.length === 0; }); const contract = currentCompileContract?.source; const contractGate = contract ? [{level: contract.equivalent ? 'pass' : 'warn', title: `Compile contract: ${contract.mode}`, detail: contract.equivalent ? 'The source artifact is preserved without semantic conversion.' : `This output is a normalized draft. Review: ${(contract.reason || []).join(', ')}.`}] : []; gateList.innerHTML = [...contractGate, ...gates].map(gate => `<article class="quality-gate ${escapeHtml(gate.level)}"><b>${escapeHtml(gate.title)}</b><p>${escapeHtml(gate.detail)}</p></article>`).join(''); if (activeSiemTab >= rules.length) activeSiemTab = 0; tabBar.innerHTML = rules.map((item, index) => `<button class="siem-tab${index === activeSiemTab ? ' active' : ''}" role="tab" id="siem-tab-${index}" aria-selected="${index === activeSiemTab ? 'true' : 'false'}" aria-controls="siem-panel-${index}" tabindex="${index === activeSiemTab ? '0' : '-1'}" data-tab="${index}">${escapeHtml(item.language)}</button>`).join(''); const focusTab = document.activeElement && document.activeElement.classList && document.activeElement.classList.contains('siem-tab') ? activeSiemTab : null; const activateTab = button => { activeSiemTab = +button.dataset.tab; renderRules(rules, gates); const next = document.querySelector(`#siem-tab-${activeSiemTab}`); if (next) next.focus(); }; tabBar.querySelectorAll('.siem-tab').forEach(button => button.addEventListener('click', () => activateTab(button))); wireRovingTablist(tabBar, activateTab); if (focusTab !== null) { const next = document.querySelector(`#siem-tab-${activeSiemTab}`); if (next) next.focus(); } list.innerHTML = rules.map((item, index) => {
    const mapping = item.field_mapping || {};
    const fidelity = item.fidelity ? `<span class="fidelity-badge ${escapeHtml(item.fidelity)}">${escapeHtml(item.fidelity)}</span>` : '';
    const validation = item.validation ? `<span class="validation-tag" title="How strongly this output was validated">validated: ${escapeHtml(item.validation)}</span>` : '';
    const chips = [
      ...(mapping.unmapped_fields || []).map(f => `<span class="unmapped-chip">unmapped: ${escapeHtml(f)}</span>`),
      // Inferred mappings (targets with no published schema) are applied, not left
      // unmapped, so without an explicit chip they would read as verified.
      ...(mapping.mapping_confidence === 'inferred'
        ? [`<span class="unmapped-chip" title="${escapeHtml(`${mapping.inferred_target || item.siem} publishes no fixed field schema; these names are inferred conventions, not verified columns. Confirm them in your environment.`)}">inferred schema: ${escapeHtml(mapping.inferred_target || item.siem)}</span>`]
        : [])
    ].join('');
    const banner = item.refused
      ? `<div class="fidelity-banner unsupported" role="alert"><b>Strict mode refused this target:</b> ${escapeHtml(item.refusal_reason || 'no faithful equivalent')}</div>`
      : ((item.fidelity === 'partial' || item.fidelity === 'unsupported')
        ? `<div class="fidelity-banner ${escapeHtml(item.fidelity)}" role="note"><b>${escapeHtml(item.fidelity)} output:</b> ${escapeHtml((item.capability_notes || [])[0] || (item.fidelity === 'unsupported' ? 'Not expressible in this dialect - see preserved source.' : 'Single-event projection - verify it matches all stages.'))}</div>`
        : '');
    const notes = ((item.capability_notes || []).length || (item.warnings || []).length || (item.checks || []).length)
      ? `<div class="capability-notes">${(item.capability_notes || []).map(n => `<p><b>Capability:</b> ${escapeHtml(n)}</p>`).join('')}${(item.warnings || []).map(w => `<p><b>Warning:</b> ${escapeHtml(w)}</p>`).join('')}${(item.checks || []).map(c => `<p><b>Check:</b> ${escapeHtml(c)}</p>`).join('')}</div>`
      : '';
    const body = item.refused
      ? `<p class="review-note"><b>No query emitted.</b> ${escapeHtml(item.review_note || '')} Strict mode refuses lossy conversions; disable it for a labelled partial draft.</p>`
      : `<div class="rule-primary">
           <div class="rule-primary-head">
             <span class="rule-primary-label">Complete rule &mdash; this is what you deploy</span>
           </div>
           <pre><code>${escapeHtml(item.rule)}</code></pre>
         </div>
         ${(item.section_blocks || []).length
           ? `<details class="section-inspector">
                <summary>Inspect rule sections</summary>
                <p class="hint">A breakdown for review only. Copy the box above to deploy.</p>
                ${(item.section_blocks || []).map((block, bi) => `<details class="section-block"><summary>${escapeHtml(String(block.title || '').replace(/^./, c => c.toUpperCase()))}<button type="button" class="section-copy" data-rule="${index}" data-block="${bi}" aria-label="Copy ${escapeHtml(block.title)} section">⧉</button></summary><pre><code>${escapeHtml(block.code)}</code></pre></details>`).join('')}
              </details>`
           : ''}${notes}<p class="rule-mapping"><strong>Field map</strong> ${escapeHtml(mapping.canonical_field || 'custom')} → ${escapeHtml(mapping.native_field || 'review required')}</p><p class="review-note"><b>Review:</b> ${escapeHtml(item.review_note)}</p>`;
    const actions = item.refused
      ? ''
      : `<div class="result-actions"><button class="copy-btn" data-index="${index}">Copy</button><button class="download-btn" data-index="${index}" aria-label="Download ${escapeHtml(item.language)} rule">↓</button></div>`;
    return `<article class="rule-result" role="tabpanel" id="siem-panel-${index}" aria-labelledby="siem-tab-${index}"${index === activeSiemTab ? '' : ' hidden'}>${banner}<header><div><span class="language-badge">${escapeHtml(item.language)}</span><h3>${escapeHtml(item.name)}</h3>${fidelity}${validation}${chips}</div>${actions}</header>${body}</article>`;
  }).join(''); output.hidden = false; announce('Compiled ' + rules.length + ' SIEM template' + (rules.length === 1 ? '' : 's') + '.'); output.scrollIntoView({behavior: 'smooth', block: 'start'}); document.querySelectorAll('.copy-btn').forEach(button => button.addEventListener('click', () => copyRule(+button.dataset.index, button))); document.querySelectorAll('.section-copy').forEach(button => button.addEventListener('click', () => copySection(+button.dataset.rule, +button.dataset.block, button))); document.querySelectorAll('.download-btn').forEach(button => button.addEventListener('click', () => downloadRule(+button.dataset.index))); }
function renderExplainerCards(exp) { const box = document.querySelector('#explainer-cards'); if (!box || !exp || !exp.bullets) return; const bullets = exp.bullets || []; const pick = (...keys) => bullets.filter(b => keys.some(k => b.toLowerCase().includes(k))); const card = (title, items) => items.length ? `<div class="explainer-card"><h4>${title}</h4><ul>${items.map(b => `<li>${escapeHtml(b)}</li>`).join('')}</ul></div>` : ''; box.innerHTML = `<div class="explainer-card"><h4>Summary</h4><p>${escapeHtml(exp.summary || '')}</p></div>` + card('Predicates', pick('predicate')) + card('Exclusions', pick('exclusion')) + card('Threshold & grouping', pick('threshold')) + card('Correlation', pick('sequence', 'join', 'aggregation', 'lookup', 'stream', 'time', 'outcome')) + card('Coverage', pick('section', 'portable', 'single-event')) + ((exp.lossy_flags || []).length ? `<div class="explainer-card flags"><h4>Review flags</h4><ul>${exp.lossy_flags.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul></div>` : ''); }
async function copyRule(index, button) { try { await navigator.clipboard.writeText(compiledRules[index].rule); button.textContent = 'Copied'; announce(`Copied ${compiledRules[index].language} rule.`); } catch { button.textContent = 'Copy failed'; announce('Copy failed: clipboard unavailable.'); } setTimeout(() => button.textContent = 'Copy', 1400); }
async function copySection(ruleIndex, blockIndex, button) { const block = (compiledRules[ruleIndex].section_blocks || [])[blockIndex]; if (!block) return; try { await navigator.clipboard.writeText(block.code); const original = button.textContent; button.textContent = '✓'; announce(`Copied ${block.title} section.`); setTimeout(() => button.textContent = original, 1400); } catch { announce('Copy failed: clipboard unavailable.'); } }
function downloadRule(index) { const rule = compiledRules[index]; const extension = {splunk:'spl', sentinel:'kql', elastic:'eql', qradar:'aql', google_secops:'yaral', falcon:'cql', wazuh:'xml', sigma:'yml'}[rule.siem] || 'txt'; const file = new Blob([rule.rule], {type:'text/plain'}); const link = Object.assign(document.createElement('a'), {href: URL.createObjectURL(file), download: `${rule.technique_label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${rule.siem}.${extension}`}); link.click(); URL.revokeObjectURL(link.href); }
function downloadBundle() { if (!currentPayload) return; const packageData = { format: 'ruleforge-rule-package/v1', exported_at: new Date().toISOString(), definition: currentPayload, quality_gates: currentQualityGates, artifacts: compiledRules }; const file = new Blob([JSON.stringify(packageData, null, 2)], {type: 'application/json'}); const link = Object.assign(document.createElement('a'), {href: URL.createObjectURL(file), download: `${currentPayload.title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-ruleforge-package.json`}); link.click(); URL.revokeObjectURL(link.href); }
async function loadHistory() { const list = document.querySelector('#history-list'); try { const response = await fetch('/api/history'); const body = await response.json(); if (!response.ok) throw new Error();     list.innerHTML = body.history.length ? body.history.map(item => { const rawRule = item.payload && item.payload.rule ? item.payload.rule : JSON.stringify(item.payload, null, 2); const details = JSON.stringify(item.details, null, 2); const version = item.version ? ` · v${escapeHtml(String(item.version))}` : ''; const parent = item.parent_id ? ` ← ${escapeHtml(String(item.parent_id))}` : ''; return `<details class="history-row"><summary><span><b>${escapeHtml(item.title)}</b><small>${escapeHtml(item.id)}${version}${parent} · ${escapeHtml(item.created_at)}</small></span><span><em class="status-badge">${escapeHtml(item.kind)}</em><small>${escapeHtml(item.siem)}</small></span><span>${escapeHtml(item.summary)}</span></summary><div class="history-detail"><p><b>Stored input</b></p><pre>${escapeHtml(rawRule)}</pre><p><b>Analysis and generated details</b></p><pre>${escapeHtml(details)}</pre></div></details>`; }).join('') : '<p class="empty-history">No rule history yet.</p>'; } catch { list.innerHTML = '<p class="empty-history">Rule history is unavailable.</p>'; } }
document.querySelector('#download-all').addEventListener('click', downloadBundle);
document.querySelector('#run-evasion').addEventListener('click', async () => {
  const box = document.querySelector('#evasion-result'); box.textContent = 'Running evasion self-test…';
  let baseEvent = null;
  try { const parsed = parseEventText(document.querySelector('#test-events').value); const first = parsed.find(e => e && typeof e === 'object' && !Array.isArray(e)); if (first) baseEvent = first; } catch {}
  if (!baseEvent) { box.innerHTML = '<div role="alert">Load a matching sample event first (use a preset).</div>'; return; }
  try {
    const response = await fetch('/api/evade', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...currentFormConditions(), event: baseEvent})});
    const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Unable to run evasion test.');
    box.innerHTML = `<strong>${escapeHtml(body.verdict)}</strong><p>Base matched: ${body.base_matched ? 'yes' : 'no'} · variants tested: ${escapeHtml(String(body.variants_tested))} · evasions: ${escapeHtml(String(body.evasions))}</p>`
      + (body.findings || []).map(f => `<p><b>${escapeHtml(f.field)}</b> evaded by <code>${escapeHtml(f.variant)}</code> → <code>${escapeHtml(f.mutated_value)}</code><br><small>${escapeHtml(f.fix || '')}</small></p>`).join('');
    announce(`Evasion self-test complete: ${body.verdict}.`);
  } catch (error) { box.innerHTML = `<div role="alert">Error: ${escapeHtml(error.message)}</div>`; }
});
let lastCompiledModel = null;
/* One reader for the threshold, so Compile and Test can never disagree again. The stepper
   clamps, but a typed value can be 2.5, -1, 10001 or 1e2. Those previously flowed through
   two different paths: Compile silently truncated with parseInt while Test sent the raw
   value and drew a 400, so the UI could display 2.5 while compiling 2. Reject instead. */
function readThreshold() {
  const raw = String(document.querySelector('#threshold').value || '').trim();
  if (!/^\d+$/.test(raw)) return { value: 1, error: 'Threshold must be a whole number, for example 5.' };
  const value = Number(raw);
  if (value < 1 || value > 10000) return { value: 1, error: 'Threshold must be between 1 and 10000.' };
  return { value, error: null };
}
function currentFormConditions() { return { conditions: [...conditionList.querySelectorAll('.condition-row')].map(row => ({field: row.querySelector('[data-condition-field]').value, operator: row.querySelector('[data-condition-operator]').value, value: row.querySelector('[data-condition-value]').value})), exclude_conditions: [...exclusionList.querySelectorAll('.condition-row')].map(row => ({field: row.querySelector('[data-condition-field]').value, operator: row.querySelector('[data-condition-operator]').value, value: row.querySelector('[data-condition-value]').value})), threshold: readThreshold().value, timeframe: document.querySelector('[name="timeframe"]').value, group_by: document.querySelector('[name="group_by"]').value, title: document.querySelector('[name="title"]').value, description: document.querySelector('#f-description').value, severity: document.querySelector('[name="severity"]').value, technique: document.querySelector('[name="technique"]').value, field: document.querySelector('[name="field"]')?.value, data_source: document.querySelector('[name="data_source"]').value, siems: [...document.querySelectorAll('[name="siems"]:checked')].map(n => n.value), condition_logic: document.querySelector('#condition-logic').value, use_threshold: thresholdToggle.checked, strict: document.querySelector('#strict').checked, correlation: currentCorrelation() }; }
/* The textarea is labelled "JSON / NDJSON / CSV", but only a JSON array ever reached the
   API. This normalises all shapes and refuses to guess when input is ambiguous: a single
   malformed NDJSON line used to fall through to the CSV branch and yield plausible-looking
   events that simply never matched, which is worse than an error. */
function splitCsvLine(line) {
  const cells = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (quoted) {
      if (char !== '"') cell += char;
      else if (line[i + 1] === '"') { cell += '"'; i++; }
      else quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === ',') { cells.push(cell); cell = ''; }
    else cell += char;
  }
  if (quoted) throw new Error('Unbalanced quote in the CSV data.');
  cells.push(cell);
  return cells.map(c => c.trim());
}
function parseEventText(text) {
  const raw = (text || '').trim();
  if (!raw) return [];
  const first = raw[0];
  if (first === '{' || first === '[') {
    try { const parsed = JSON.parse(raw); return Array.isArray(parsed) ? parsed : [parsed]; }
    catch (error) {
      const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      if (lines.every(l => l.startsWith('{'))) {
        try { return lines.map(l => JSON.parse(l)); }
        catch (inner) { throw new Error(`That looks like NDJSON, but a line is not valid JSON: ${inner.message}`); }
      }
      throw new Error(`That looks like JSON but does not parse: ${error.message}`);
    }
  }
  const rows = raw.split(/\r?\n/).filter(l => l.trim());
  if (rows.length < 2) throw new Error('CSV needs a header row and at least one event row.');
  const header = splitCsvLine(rows[0]);
  if (header.some(h => !h)) throw new Error('The CSV header row has an empty column name.');
  if (new Set(header).size !== header.length) throw new Error('The CSV header row has duplicate column names.');
  const coerce = v => (v === 'true' ? true : v === 'false' ? false
    : v !== '' && !isNaN(Number(v)) ? Number(v) : v);
  return rows.slice(1).map((row, index) => {
    const cells = splitCsvLine(row);
    if (cells.length !== header.length) {
      throw new Error(`CSV row ${index + 2} has ${cells.length} value(s) but the header declares ${header.length}.`);
    }
    return Object.fromEntries(cells.map((v, i) => [header[i], coerce(v)]));
  });
}
document.querySelector('#run-match-test').addEventListener('click', async () => {
  const box = document.querySelector('#tester-result'); box.textContent = 'Evaluating…';
  let events; try { events = parseEventText(document.querySelector('#test-events').value); } catch (error) { box.textContent = error.message; return; }
  if (!events.length) { box.textContent = 'Load sample events first (a preset, or a JSON array / NDJSON / CSV).'; return; }
  try { const response = await fetch('/api/test_match', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...currentFormConditions(), events})}); const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Unable to evaluate.');
    const num = value => escapeHtml(String(value));
    const rows = body.per_event.map(e => `<tr><td>${num(e.index)}</td><td class="${e.matched ? 'match-yes' : e.suppressed_by_exclusion ? 'match-suppressed' : 'match-no'}">${e.matched ? 'MATCH' : e.suppressed_by_exclusion ? 'SUPPRESSED' : 'no match'}</td><td>${e.reasons.map(r => `<code>${escapeHtml(r)}</code>`).join('<br>')}</td></tr>`).join('');
    const scoring = body.scoring || {};
    const scoreHtml = (scoring.tp !== undefined && (scoring.tp + scoring.fp + scoring.fn + scoring.tn) > 0) ? `<p><b>Test performance:</b> precision ${scoring.precision === null ? '—' : Math.round(scoring.precision * 100) + '%'} · recall ${scoring.recall === null ? '—' : Math.round(scoring.recall * 100) + '%'} · benign fire rate ${scoring.benign_fire_rate === null ? '—' : Math.round(scoring.benign_fire_rate * 100) + '%'} (TP ${num(scoring.tp)} / FP ${num(scoring.fp)} / FN ${num(scoring.fn)} / TN ${num(scoring.tn)})</p>${scoring.volume_note ? `<p><b>Volume:</b> ${escapeHtml(scoring.volume_note)}</p>` : ''}` : '';
    const partitions = body.partitions ? `<p><b>Per-group counts:</b> ${Object.entries(body.partitions).map(([k, v]) => `${escapeHtml(k)}: ${num(v)}`).join(' · ')}</p>` : '';
    box.innerHTML = `<strong>Verdict: ${escapeHtml(body.verdict)} (${num(body.matched)}/${num(body.total)}, threshold ${num(body.threshold)})</strong>${(lastCompiledModel && lastCompiledModel.fidelity && lastCompiledModel.fidelity !== 'exact') ? `<p><b>Tuned model fidelity:</b> ${escapeHtml(lastCompiledModel.fidelity)} - these numbers describe the model, not necessarily the emitted query.</p>` : ''}${body.count_detail ? `<p><b>Detail:</b> ${escapeHtml(body.count_detail)}</p>` : ''}${body.window_valid === false ? `<p><b>Window:</b> invalid window value — results used a 5m default.</p>` : ''}<div class="table-scroll"><table class="match-table"><thead><tr><th>Event</th><th>Result</th><th>Clause-by-clause reason</th></tr></thead><tbody>${rows}</tbody></table></div>${scoreHtml}${partitions}` + (body.notes || []).map(n => `<p><small>${escapeHtml(n)}</small></p>`).join('');
    announce(`Match test complete: ${body.verdict}, ${body.matched} of ${body.total} events matched.`);
  } catch (error) { box.innerHTML = `<div role="alert">Error: ${escapeHtml(error.message)}</div>`; }
});
function fixtureEvents() {
  let parsed;
  try { parsed = parseEventText(document.querySelector('#test-events').value); }
  catch (error) { throw new Error(error.message); }
  if (!parsed.length) throw new Error('Load sample events first (a preset, or a JSON array / NDJSON / CSV).');
  /* Reject rather than filter. Dropping non-objects saved a partial fixture without
     saying so, and an all-primitive payload was reported as "no events loaded" when the
     analyst had in fact loaded events - just invalid ones. */
  const offender = parsed.findIndex(e => !e || typeof e !== 'object' || Array.isArray(e));
  if (offender >= 0) throw new Error(`Event ${offender + 1} is not a JSON object. A fixture cannot contain bare values.`);
  return parsed;
}
/* storage.save_fixture coerces anything it does not recognise to false, so an unusable
   label would silently become "this event must not fire" and skew every replay score. */
const EXPECTED_TRUE = new Set(['true', 'yes', '1', 'malicious', 'expected']);
const EXPECTED_FALSE = new Set(['false', 'no', '0', 'benign', 'unexpected', 'not expected']);
function expectedLabel(event) {
  if (!('_expected' in event)) return undefined;
  const value = event._expected;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const key = value.trim().toLowerCase();
    if (EXPECTED_TRUE.has(key)) return true;
    if (EXPECTED_FALSE.has(key)) return false;
  }
  return null;
}
document.querySelector('#save-fixture').addEventListener('click', async () => {
  const box = document.querySelector('#fixture-result');
  let events; try { events = fixtureEvents(); } catch (error) { box.innerHTML = `<div role="alert">Error: ${escapeHtml(error.message)}</div>`; return; }
  try {
    const title = window.prompt('Fixture name (ties these events to a rule):', document.querySelector('[name="title"]').value || 'fixture');
    if (!title) return;
    /* storage.save_fixture rejects any event without an _expected label. The shipped
       presets deliberately carry none, because a label feeds the TP/FP scoring in
       match_tester and would silently change every Test verdict. So label at save time,
       with the analyst confirming the assertion rather than it being assumed. */
    const unusable = events.filter(e => expectedLabel(e) === null);
    if (unusable.length) {
      box.innerHTML = `<div role="alert">Error: ${unusable.length} event(s) have an <code>_expected</code> value that is not true or false. Storing it would silently record those events as "must not fire" and corrupt replay scoring.</div>`;
      return;
    }
    const unlabelled = events.filter(e => expectedLabel(e) === undefined);
    if (unlabelled.length) {
      const proceed = window.confirm(
        `${unlabelled.length} of ${events.length} event(s) have no _expected label, which a fixture requires.\n\n` +
        `OK = label all of them as SHOULD FIRE this rule\nCancel = stop, so you can add _expected true/false yourself`);
      if (!proceed) {
        box.innerHTML = '<div role="alert">Fixture not saved. Add <code>_expected</code> true/false to each event, or press OK to label them all.</div>';
        return;
      }
      unlabelled.forEach(event => { event._expected = true; });
    }
    const response = await fetch('/api/fixtures', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({title, events})});
    const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Unable to save fixture.');
    box.innerHTML = `<strong>Fixture saved:</strong> ${escapeHtml(body.title)} · ${numOr(body.events)} events with pinned expectations.`;
    announce(`Fixture ${body.title} saved.`);
  } catch (error) { box.innerHTML = `<div role="alert">Error: ${escapeHtml(error.message)}</div>`; }
});
document.querySelector('#replay-fixtures').addEventListener('click', async () => {
  const box = document.querySelector('#fixture-result'); box.textContent = 'Replaying fixtures…';
  try {
    const list = await (await fetch('/api/fixtures')).json();
    if (!list.fixtures.length) { box.innerHTML = '<p>No fixtures saved yet.</p>'; return; }
    const ids = list.fixtures.map(f => f.id);
    const response = await fetch('/api/fixtures/replay', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...currentFormConditions(), fixture_ids: ids})});
    const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Unable to replay fixtures.');
    const rows = (body.results || []).map(r => `<tr><td>${escapeHtml(r.title)}</td><td>${r.passed ? 'PASS' : 'FAIL'}</td><td>${r.event_count}</td><td>${(r.mismatches || []).length}</td></tr>`).join('');
    box.innerHTML = `<strong>Fixture replay: ${body.passed_count}/${body.total} passed</strong><div class="table-scroll"><table class="match-table"><thead><tr><th>Fixture</th><th>Result</th><th>Events</th><th>Mismatches</th></tr></thead><tbody>${rows}</tbody></table></div>`;
    announce(`Fixture replay: ${body.passed_count} of ${body.total} passed.`);
  } catch (error) { box.innerHTML = `<div role="alert">Error: ${escapeHtml(error.message)}</div>`; }
});
function numOr(value) { return escapeHtml(String(value ?? '')); }
document.querySelector('#run-diff').addEventListener('click', async () => {
  const box = document.querySelector('#diff-result'); if (!lastCompiledModel) { box.textContent = 'Compile a rule first, then tune and diff.'; return; }
  const form = document.querySelector('#rule-form'); const data = Object.fromEntries(new FormData(form).entries());
  try { const nowResp = await fetch('/api/compile', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...currentFormConditions(), title: data.title, siems: currentFormConditions().siems.length ? currentFormConditions().siems : ['splunk']})}); const nowBody = await nowResp.json(); if (!nowResp.ok) throw new Error(nowBody.error || 'Unable to compile.');
    let tuneEvents = []; try { tuneEvents = parseEventText(document.querySelector('#test-events').value).filter(e => e && typeof e === 'object' && !Array.isArray(e)); } catch {}
    const diffResp = await fetch('/api/diff', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({before: lastCompiledModel, after: nowBody.model, events: tuneEvents})}); const diff = await diffResp.json();
    const settingRows = (diff.setting_changes || []).map(c => `<tr><td>${escapeHtml(c.setting)}</td><td><code>${escapeHtml(JSON.stringify(c.before))}</code></td><td><code>${escapeHtml(JSON.stringify(c.after))}</code></td></tr>`).join('');
    box.innerHTML = `<div class="table-scroll"><table class="diff-table"><thead><tr><th>Change</th><th>Before</th><th>After</th></tr></thead><tbody>`
      + diff.added.map(a => `<tr><td class="diff-add">+ added clause</td><td>—</td><td><code>${escapeHtml(a)}</code></td></tr>`).join('')
      + diff.removed.map(r => `<tr><td class="diff-remove">− removed clause</td><td><code>${escapeHtml(r)}</code></td><td>—</td></tr>`).join('')
      + settingRows + `</tbody></table></div>`
      + (diff.verdict_before !== undefined ? `<p><b>Tune impact:</b> verdict ${escapeHtml(diff.verdict_before)} → ${escapeHtml(diff.verdict_after)}${diff.verdict_changed ? ' (changed)' : ' (unchanged)'}</p>` : '')
      + (diff.scoring_before && diff.scoring_after ? `<p><b>Score delta:</b> TP ${diff.scoring_before.tp}→${diff.scoring_after.tp} · FP ${diff.scoring_before.fp}→${diff.scoring_after.fp} · FN ${diff.scoring_before.fn}→${diff.scoring_after.fn} · TN ${diff.scoring_before.tn}→${diff.scoring_after.tn}</p>` : '');
    announce('Diff complete.');
  } catch (error) { box.innerHTML = `<div role="alert">Error: ${escapeHtml(error.message)}</div>`; }
});
async function loadCoverage() {
  const matrix = document.querySelector('#coverage-matrix'); const summary = document.querySelector('#coverage-summary');
  if (!matrix || !summary) return;
  try {
    const body = await (await fetch('/api/coverage')).json();
    if (!body || !body.techniques) { matrix.innerHTML = '<p>Coverage unavailable.</p>'; return; }
    summary.innerHTML = Object.entries(body.summary).map(([siem, counts]) =>
      `<div class="coverage-card"><b>${escapeHtml(siem)}</b>` +
      Object.entries(counts).map(([level, n]) => `<span class="${escapeHtml(level)}">${n} ${escapeHtml(level.replace('_', ' '))}</span>`).join('') +
      `</div>`).join('');
    const head = `<tr><th>technique</th>${body.targets.map(t => `<th>${escapeHtml(t)}</th>`).join('')}</tr>`;
    const rows = body.techniques.map(row =>
      `<tr><td>${escapeHtml(row.label)}${row.mitre && row.mitre.length ? ` <small>${escapeHtml(row.mitre.join(','))}</small>` : ''}</td>` +
      body.targets.map(t => { const cell = row.targets[t] || {}; return `<td class="coverage-cell ${escapeHtml(cell.fidelity || 'unknown')}" title="${escapeHtml(cell.validation || '')}">${escapeHtml(cell.fidelity || '?')}</td>`; }).join('') +
      `</tr>`).join('');
    matrix.innerHTML = `<table class="coverage-table"><thead>${head}</thead><tbody>${rows}</tbody></table>` +
      ((body.families || []).length ? `<h3 style="margin:18px 0 8px;font-size:13px">Advanced families</h3><table class="coverage-table"><thead>${head}</thead><tbody>` +
        body.families.map(row =>
          `<tr><td>${escapeHtml(row.label)}</td>` +
          body.targets.map(t => { const cell = row.targets[t] || {}; return `<td class="coverage-cell ${escapeHtml(cell.fidelity || 'unknown')}" title="${escapeHtml(cell.validation || '')}">${escapeHtml(cell.fidelity || '?')}</td>`; }).join('') +
          `</tr>`).join('') + `</tbody></table>` : '');
  } catch { matrix.innerHTML = '<p>Coverage unavailable.</p>'; }
}
let attackIndex = null;
async function loadAttack() {
  const list = document.querySelector('#attack-list'); const summary = document.querySelector('#attack-summary');
  const search = document.querySelector('#attack-search');
  if (!list || !summary) return;
  try {
    const body = await (await fetch('/api/attack')).json();
    attackIndex = body.techniques || [];
    summary.textContent = `${attackIndex.length} MITRE ATT&CK techniques, ${body.buildable} with a ready template in this tool. Unmapped techniques are reference only.`;
    const draw = () => {
      const q = (search.value || '').trim().toLowerCase();
      const rows = (q ? attackIndex.filter(t => (t.id + ' ' + t.name + ' ' + (t.tactics || []).join(' ')).toLowerCase().includes(q)) : attackIndex).slice(0, 300);
      list.innerHTML = rows.length ? rows.map(t => {
        const inner = `<code>${escapeHtml(t.id)}</code><span>${escapeHtml(t.name)} <small style="color:var(--muted)">${escapeHtml((t.summary || '').slice(0, 110))}</small></span><span class="${t.buildable ? 'buildable' : 'tactic'}">${t.buildable ? 'template' : escapeHtml((t.tactics || []).join(', '))}</span>`;
        /* data-technique must carry the INTERNAL template id, because #technique is keyed
           by patternDefaults. Passing the MITRE id made the loaded form fail the submit
           guard with "Choose a behavior pattern from the list." */
        return t.buildable && (t.templates || []).length
          ? `<button type="button" class="attack-row" data-technique="${escapeHtml(t.templates[0])}" data-mitre="${escapeHtml(t.id)}" title="Load the ${escapeHtml(t.templates[0])} template into the composer">${inner}</button>`
          : `<div class="attack-row static">${inner}</div>`;
      }).join('') : '<p class="empty-history">No technique matches.</p>';
    };
    /* Delegation, installed once. Binding every row on every redraw leaked a listener per
       visit to the tab, so one keystroke eventually triggered N full redraws. */
    if (!list.dataset.clicked) {
      list.dataset.clicked = 'true';
      list.addEventListener('click', event => {
        const button = event.target.closest('.attack-row[data-technique]');
        if (!button || !list.contains(button)) return;
        const field = document.querySelector('#technique');
        field.value = button.dataset.technique;
        field.dispatchEvent(new Event('change', { bubbles: true }));
        showTab('compose');
        const templates = (attackIndex.find(t => t.id === button.dataset.mitre) || {}).templates || [];
        announce(`Loaded ${button.dataset.technique} into the composer` +
          (templates.length > 1 ? ` (first of ${templates.length} templates for ${button.dataset.mitre}).` : '.'));
      });
    }
    if (!search.dataset.wired) { search.dataset.wired = 'true'; search.addEventListener('input', draw); }
    draw();
  } catch { summary.textContent = 'ATT&CK catalog unavailable.'; }
}
document.querySelector('#refresh-history').addEventListener('click', loadHistory);
loadAttack();
loadCoverage();
const eventPresets = {
  match: [{ 'process.name': 'powershell.exe', 'process.command_line': 'powershell -enc aGVsbG8=', 'user.name': 'alice', 'host.name': 'ws-01' }, { 'process.name': 'powershell.exe', 'process.command_line': 'powershell -enc d29ybGQ=', 'user.name': 'alice', 'host.name': 'ws-01' }],
  excluded: [{ 'process.name': 'powershell.exe', 'process.command_line': 'powershell -enc aGVsbG8=', 'user.name': 'trusted-admin', 'host.name': 'ws-01' }],
  nomatch: [{ 'process.name': 'explorer.exe', 'process.command_line': 'explorer /factory', 'user.name': 'bob', 'host.name': 'ws-02' }]
};
document.querySelectorAll('[data-preset]').forEach(button => button.addEventListener('click', () => { document.querySelector('#test-events').value = JSON.stringify(eventPresets[button.dataset.preset], null, 2); announce(`${button.textContent.trim()} loaded into sample events.`); }));
let ingestFileToken = 0;
document.querySelector('#ingest-file').addEventListener('change', event => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  /* The file input shipped with no handler and Ingest only ever read the textarea, so
     selecting a file did nothing. Load it into the textarea and preselect the format;
     Ingest itself still reads the textarea, so paste and file share one code path. */
  const token = ++ingestFileToken;
  const ext = (file.name.split('.').pop() || '').toLowerCase();
  const format = ext === 'ndjson' || ext === 'jsonl' ? 'ndjson' : ext === 'csv' ? 'csv' : 'json';
  document.querySelector('#ingest-format').value = format;
  const reader = new FileReader();
  reader.onload = () => {
    /* Two quick selections could resolve out of order, leaving the older file's contents
       in the textarea. Only the most recent selection may write. */
    if (token !== ingestFileToken) return;
    document.querySelector('#test-events').value = String(reader.result || '');
    announce(`${file.name} loaded as ${format}. Choose Ingest to parse it.`);
  };
  reader.onerror = () => {
    if (token !== ingestFileToken) return;
    document.querySelector('#ingest-status').innerHTML = '<div role="alert">Could not read that file.</div>';
  };
  reader.readAsText(file);
});
document.querySelector('#run-ingest').addEventListener('click', async () => {
  const box = document.querySelector('#ingest-status'); box.textContent = 'Ingesting…';
  try {
    const response = await fetch('/api/ingest', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({content: document.querySelector('#test-events').value, format: document.querySelector('#ingest-format').value})});
    const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Unable to ingest.');
    document.querySelector('#test-events').value = JSON.stringify(body.events);
    const known = new Set([...document.querySelectorAll('#field-names option')].map(o => o.value));
    const fresh = (body.fields || []).filter(f => !known.has(f));
    const list = document.querySelector('#field-names');
    fresh.forEach(f => { const opt = document.createElement('option'); opt.value = f; list.appendChild(opt); });
    box.innerHTML = `<strong>${body.events.length} events ingested (${escapeHtml(body.format)}) · ${body.fields.length} fields discovered${fresh.length ? `, ${fresh.length} new in autocomplete` : ''}.</strong>` + (body.warnings || []).map(w => `<p><small>${escapeHtml(w)}</small></p>`).join('');
    announce(`Ingested ${body.events.length} events, ${body.fields.length} fields discovered.`);
  } catch (error) { box.innerHTML = `<div role="alert">Error: ${escapeHtml(error.message)}</div>`; }
});
function syncThrValue() { document.querySelector('#thr-value').textContent = document.querySelector('#threshold').value; }
document.querySelector('#thr-minus').addEventListener('click', () => { const input = document.querySelector('#threshold'); input.value = Math.max(1, (+input.value || 1) - 1); syncThrValue(); });
document.querySelector('#thr-plus').addEventListener('click', () => { const input = document.querySelector('#threshold'); input.value = Math.min(10000, (+input.value || 1) + 1); syncThrValue(); });
document.querySelectorAll('[data-window]').forEach(button => button.addEventListener('click', () => { document.querySelector('[name="timeframe"]').value = button.dataset.window; document.querySelectorAll('[data-window]').forEach(b => { const on = b === button; b.classList.toggle('on', on); b.setAttribute('aria-pressed', on ? 'true' : 'false'); }); announce(`Time window set to ${button.dataset.window}.`); }));
/* Header counters: populated on load so the workbench does not open on em-dashes.
   They live in the Mappings view's data source, but a user should not have to visit
   another mode to learn what this build actually covers. */
async function loadHeaderStats() {
  try {
    const response = await fetch('/api/techniques');
    const body = await response.json();
    if (!response.ok) return;
    const techniques = document.querySelector('#stat-techniques');
    if (techniques) techniques.textContent = String((body.techniques || []).length || '—');
    const mapped = document.querySelector('#stat-mapped');
    if (mapped) mapped.textContent = String(body.mapped_field_count || '—');
    const homeTechniques = document.querySelector('#home-techniques');
    if (homeTechniques) homeTechniques.textContent = String((body.techniques || []).length || '—');
    const homeMapped = document.querySelector('#home-mapped');
    if (homeMapped) homeMapped.textContent = String(body.mapped_field_count || '—');
  } catch { /* the header is supplementary; the workbench works without it */ }
}
loadHeaderStats();

/* ══ Mappings view: org-specific pins + built-in provenance ═════════ */

async function loadMappings() {
  const list = document.querySelector('#ov-list');
  const count = document.querySelector('#ov-count');
  const provenance = document.querySelector('#ov-provenance');
  try {
    const response = await fetch('/api/mappings/overrides');
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || 'unavailable');
    if (count) count.textContent = String(body.count || 0);
    const entries = Object.entries(body.overrides || {});
    if (list) {
      list.innerHTML = entries.length
        ? entries.flatMap(([target, table]) => Object.entries(table).map(([field, native]) => {
            const note = (body.notes || {})[`${target}:${field}`] || {};
            return `<div class="model-row" style="grid-template-columns:1.1fr 1.1fr 2fr auto;align-items:center">`
              + `<code>${escapeHtml(field)}</code><code>${escapeHtml(native)}</code>`
              + `<small class="hint">${escapeHtml(note.reason || 'no reason recorded')}`
              + `${note.author ? ` &mdash; ${escapeHtml(note.author)}` : ''}</small>`
              + `<button type="button" class="remove-condition" data-ov-remove="${escapeHtml(target)}" `
              + `data-ov-field="${escapeHtml(field)}" aria-label="Remove mapping ${escapeHtml(field)}">&times;</button></div>`;
          })).join('')
        : '<p class="hint">No pins yet. Your overrides win over the built-in table and are stored with a reason.</p>';
      list.querySelectorAll('[data-ov-remove]').forEach(button => button.addEventListener('click', async () => {
        await postOverride({target: button.dataset.ovRemove, canonical_field: button.dataset.ovField}, 'DELETE');
      }));
    }
  } catch { if (list) list.innerHTML = '<p class="hint">Mappings are unavailable.</p>'; }
  try {
    const response = await fetch('/api/techniques');
    const body = await response.json();
    const targets = (body.provenance || {}).targets || {};
    if (provenance) {
      provenance.innerHTML = Object.entries(targets).map(([name, entry]) => `
        <div class="provenance-item">
          <b>${escapeHtml(name)} <span class="pill conf-${escapeHtml(entry.confidence)}">${escapeHtml(entry.confidence)}</span></b>
          <small class="hint">${escapeHtml(entry.schema)} &middot; ${escapeHtml(entry.version)}</small>
          <code>${escapeHtml(entry.source_url)}</code>
          <p class="hint">${escapeHtml(entry.notes || '')}</p>
        </div>`).join('');
    }
    const mapped = document.querySelector('#stat-mapped');
    if (mapped && body.mapped_field_count) mapped.textContent = String(body.mapped_field_count);
    const tech = document.querySelector('#stat-techniques');
    if (tech && body.techniques) tech.textContent = String(body.techniques.length);
  } catch { /* provenance is supplementary; the workbench works without it */ }
}

const overrideStatus = document.querySelector('#ov-status');
async function postOverride(payload, method) {
  let response;
  try {
    response = await fetch('/api/mappings/overrides', {
      method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
    });
  } catch { return false; }
  const body = await response.json().catch(() => ({}));
  if (overrideStatus) {
    overrideStatus.innerHTML = response.ok
      ? '<p style="color:var(--ok)">Saved. This mapping now wins over the built-in table.</p>'
      : `<p style="color:var(--bad)">${escapeHtml(body.error || 'Could not save that mapping.')}</p>`;
  }
  if (response.ok) loadMappings();
  return response.ok;
}

document.querySelector('#ov-save')?.addEventListener('click', () => postOverride({
  target: document.querySelector('#ov-target').value,
  canonical_field: document.querySelector('#ov-canonical').value,
  native_field: document.querySelector('#ov-native').value,
  reason: document.querySelector('#ov-reason').value,
  author: 'analyst',
}, 'POST'));

document.querySelector('#ov-clear')?.addEventListener('click', () => postOverride({
  target: document.querySelector('#ov-target').value,
  canonical_field: document.querySelector('#ov-canonical').value,
}, 'DELETE'));

syncThrValue();
document.querySelector('#clear-history').addEventListener('click', async () => { if (!window.confirm('Clear all saved rule history?')) return; const response = await fetch('/api/history', {method: 'DELETE'}); if (response.ok) loadHistory(); });
loadHistory();

/* ══ Home dashboard ═══════════════════════════════════════════════════ */

async function loadHome() {
  /* showPrimary('home') fires during init and the top-level call fires again, which
     would double every request on first paint. One in-flight run; re-entry is a no-op. */
  if (homeLoading) return;
  homeLoading = true;
  try {
    await renderHome();
  } finally { homeLoading = false; }
}

async function renderHome() {
  const coverage = document.querySelector('#home-coverage');
  const coveragePill = document.querySelector('#home-coverage-pill');
  const buildable = document.querySelector('#home-buildable');
  const historyBox = document.querySelector('#home-history');
  const historyPill = document.querySelector('#home-history-pill');
  if (coverage) {
    try {
      const body = await (await fetch('/api/coverage')).json();
      if (!body || !body.summary) throw new Error('unavailable');
      const totals = {};
      for (const counts of Object.values(body.summary)) {
        for (const [level, n] of Object.entries(counts)) totals[level] = (totals[level] || 0) + n;
      }
      const order = ['exact', 'safe_normalized', 'partial', 'unsupported', 'failed', 'unknown'];
      coverage.innerHTML = Object.keys(totals).sort((a, b) => order.indexOf(a) - order.indexOf(b))
        .map(level => `<div><b>${totals[level]}</b><span>${escapeHtml(level.replace(/_/g, ' '))}</span></div>`).join('');
      if (coveragePill) coveragePill.textContent = `${body.targets.length} targets × ${body.techniques.length} patterns`;
    } catch {
      coverage.innerHTML = '<div><b>—</b><span>unavailable</span></div>';
      if (coveragePill) coveragePill.textContent = 'unavailable';
    }
  }
  if (buildable) {
    try {
      const body = await (await fetch('/api/attack')).json();
      buildable.textContent = String(body.buildable || 0);
    } catch { buildable.textContent = '—'; }
  }
  if (historyBox) {
    try {
      const body = await (await fetch('/api/history')).json();
      const all = body.history || [];
      if (historyPill) historyPill.textContent = String(all.length);
      historyBox.innerHTML = all.length
        ? all.slice(0, 5).map(item => `<div class="history-item"><b>${escapeHtml(item.title)}</b><small>${escapeHtml(item.siem)} · ${escapeHtml(item.created_at)}</small><button type="button" class="btn ghost" data-jump="history">Open</button></div>`).join('')
        : '<p class="hint">No history yet.</p>';
      historyBox.querySelectorAll('[data-jump]').forEach(button => button.addEventListener('click', () => showTab('history')));
    } catch { historyBox.innerHTML = '<p class="hint">History is unavailable.</p>'; }
  }
}
loadHome();
