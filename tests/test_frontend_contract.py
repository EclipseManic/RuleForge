"""The frontend contract between the served HTML and static/app.js.

A full UI rewrite can look perfect, pass every backend test, and still be completely
non-functional: app.js wires itself to the document by element id, and nothing in the
Python suite checks that those ids exist. These tests make that invisible failure mode
loud. They read the ids app.js actually looks up and assert the server serves them.

If a redesign removes or renames an element, these fail immediately instead of the UI
silently doing nothing in a browser.
"""
import re
import unittest
from pathlib import Path

from app import create_app

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "static" / "app.js"

# Ids app.js creates at runtime rather than expecting in the served document.
DYNAMIC_PREFIXES = ("siem-tab-", "siem-panel-")
# Classes app.js creates at runtime rather than expecting in the served document.
DYNAMIC_CLASSES = frozenset({"condition-row"})
# Ids that belong to a sibling script block or are injected by Jinja variables that may
# legitimately be absent for a default render.
OPTIONAL_IDS = frozenset()


def _referenced_ids(source: str) -> set[str]:
    """Element ids app.js resolves, via getElementById or querySelector('#id')."""
    found: set[str] = set()
    for pattern in (
        r"getElementById\(\s*'([A-Za-z][A-Za-z0-9_-]*)'\s*\)",
        r"""getElementById\(\s*"([A-Za-z][A-Za-z0-9_-]*)"\s*\)""",
        r"querySelector\(\s*'#([A-Za-z][A-Za-z0-9_-]*)'\s*\)",
        r"""querySelector\(\s*"#([A-Za-z][A-Za-z0-9_-]*)"\s*\)""",
    ):
        found.update(re.findall(pattern, source))
    return {i for i in found if not i.startswith(DYNAMIC_PREFIXES)} - OPTIONAL_IDS


def _rendered_classes(source: str) -> set[str]:
    """Class names app.js puts into class attributes in its HTML templates."""
    found: set[str] = set()
    for match in re.finditer(r'class="([^"$]+)"', source):
        found.update(c for c in match.group(1).split() if c and "$" not in c)
    return found - DYNAMIC_CLASSES


def _selected_classes(source: str) -> set[str]:
    """Class names app.js selects by class, e.g. querySelectorAll('.view')."""
    return set(re.findall(
        r"querySelector(?:All)?\(\s*['\"]\.([A-Za-z][A-Za-z0-9_-]*)['\"]\s*\)", source))


def _emitted_class_tokens(source: str) -> set[str]:
    """Class names app.js can put into a class attribute.

    Only the literal text of the attribute, plus string literals nested inside a
    `${...}` interpolation, count as class names. Scraping every identifier would also
    harvest `escapeHtml`, `item` and `fidelity` out of
    `class="fidelity-badge ${escapeHtml(item.fidelity)}"`, which would let a genuine
    class mismatch pass unnoticed because an unrelated token happened to match.
    """
    tokens: set[str] = set()
    for match in re.finditer(r'class="([^"]*)"', source):
        value = match.group(1)
        tokens.update(re.findall(r"[A-Za-z][A-Za-z0-9_-]*", re.sub(r"\$\{.*?\}", " ", value)))
        for interpolation in re.findall(r"\$\{(.*?)\}", value):
            for quoted in re.findall(r"['\"]([^'\"]*)['\"]", interpolation):
                tokens.update(re.findall(r"[A-Za-z][A-Za-z0-9_-]*", quoted))
    for match in re.finditer(r"\.className\s*=\s*['\"]([^'\"]+)['\"]", source):
        tokens.update(match.group(1).split())
    return tokens


def _srgb(channel: int) -> float:
    c = channel / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _luminance(hex_colour: str) -> float:
    h = hex_colour.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _srgb(r) + 0.7152 * _srgb(g) + 0.0722 * _srgb(b)


def _contrast(fg: str, bg: str) -> float:
    """WCAG 2.1 relative-contrast ratio. No dependency, so it always runs."""
    a, b = _luminance(fg), _luminance(bg)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def _tokens(styles: str, scope: str = ":root") -> dict[str, str]:
    block = re.search(re.escape(scope) + r"\s*\{(.*?)\n\}", styles, re.DOTALL)
    if not block:
        raise AssertionError(f"could not find {scope} in styles.css")
    return dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{3,6})", block.group(1)))


class FrontendContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = create_app().test_client()
        cls.html = cls.client.get("/").get_data(as_text=True)
        cls.source = APP_JS.read_text(encoding="utf-8")

    def test_every_id_app_js_looks_up_exists_in_the_served_page(self):
        referenced = _referenced_ids(self.source)
        self.assertGreater(len(referenced), 30,
                           msg="id extraction looks broken; the contract would be vacuous")
        missing = sorted(i for i in referenced if f'id="{i}"' not in self.html)
        self.assertEqual(missing, [],
                         msg="app.js expects these ids but the page does not serve them")

    def test_dynamically_created_ids_are_not_required_statically(self):
        """Guard the test itself: dynamic ids must not be demanded from the server."""
        for prefix in DYNAMIC_PREFIXES:
            self.assertNotIn(prefix.rstrip("-"), _referenced_ids(self.source),
                             msg="dynamic prefix leaked into the static contract")

    def test_served_page_loads_the_script_and_stylesheet_it_depends_on(self):
        self.assertIn("/static/app.js", self.html)
        self.assertIn("/static/styles.css", self.html)
        for asset in re.findall(r'(?:href|src)="(/static/[^"]+)"', self.html):
            response = self.client.get(asset)
            self.assertEqual(response.status_code, 200, msg=asset)

    def test_every_class_app_js_selects_is_resolvable(self):
        """A class app.js selects must be in the served page or created by app.js.

        This is not hypothetical: a rebuild renamed `.generate-btn`, which threw
        'Cannot set properties of null' on load and silently stopped the compile button.
        A proximity heuristic for "app.js writes to this class" proved too brittle - it
        silently stopped detecting anything once a refactor moved one statement further
        away - so this asserts resolvability instead, which is what actually matters.
        """
        selected = _selected_classes(self.source)
        self.assertGreater(len(selected), 5, msg="class extraction looks broken")
        emitted = _emitted_class_tokens(self.source)
        unresolvable = sorted(c for c in selected
                              if f'"{c}"' not in self.html and f"'{c}'" not in self.html
                              and c not in emitted)
        self.assertEqual(unresolvable, [],
                         msg=("app.js selects these classes but neither the page nor app.js "
                              f"ever creates them: {unresolvable}"))

    def test_condition_rows_are_created_by_script_not_markup(self):
        """Guard the exemption: .condition-row is added by addCondition, so its absence
        from the served HTML is correct - but it must still be created in code."""
        for builder in ("addCondition", "addStage"):
            self.assertIn(builder, self.source, msg=f"{builder} must exist to build rows")

    def test_every_rendered_class_is_styled(self):
        """A class app.js renders but the stylesheet does not define renders unstyled.

        A rebuild styled `.attack-item` while app.js emits `.attack-row`, so the whole
        ATT&CK grid collapsed into unreadable columns. Names built by string
        interpolation are excluded, since those cannot be statically resolved.
        """
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        rendered = _rendered_classes(self.source)
        self.assertGreater(len(rendered), 15, msg="class extraction looks broken")
        unstyled = sorted(c for c in rendered if f".{c}" not in styles)
        self.assertEqual(unstyled, [],
                         msg=f"app.js renders these classes but styles.css never styles them: {unstyled}")

    def test_no_duplicate_ids_in_the_served_page(self):
        """Duplicate ids silently break label/for and ARIA relationships."""
        ids = re.findall(r'\sid="([^"]+)"', self.html)
        duplicates = {i for i in ids if ids.count(i) > 1}
        self.assertEqual(duplicates, set(), msg=f"duplicate element ids: {sorted(duplicates)}")

    def test_every_form_control_has_an_accessible_name(self):
        """Inputs must be labelled; an unlabelled control is unusable with a screen reader.

        Two valid labellings are accepted: an explicit <label for="id">, or the control
        nested inside its own <label> (implicit association).
        """
        html = self.html
        for match in re.finditer(r"<(input|select|textarea)\b[^>]*>", html):
            tag = match.group(0)
            identifier = re.search(r'\sid="([^"]+)"', tag)
            if identifier and f'for="{identifier.group(1)}"' in html:
                continue  # explicitly labelled
            preceding = html[max(0, match.start() - 400):match.start()]
            if preceding.rsplit("<label", 1)[0] != preceding and "</label>" not in preceding.rsplit("<label", 1)[-1]:
                continue  # still inside an enclosing <label> (implicit association)
            self.assertTrue('aria-label' in tag or 'aria-labelledby' in tag,
                            msg=f"control is not labelled: {tag[:120]}")

    def test_single_main_landmark_and_one_h1(self):
        self.assertEqual(len(re.findall(r"<main\b", self.html)), 1)
        self.assertGreaterEqual(len(re.findall(r"<h1\b", self.html)), 1)

    def test_interactive_nav_is_operable_by_keyboard(self):
        """Both nav levels must be real ARIA tablists with roving tabindex wiring.

        A third tablist is expected: #siem-tabs, the per-target output switcher, which is
        built at runtime rather than served, so the assertion is on the two nav ids.
        """
        for list_id in ("primary-tabs", "sub-tabs"):
            self.assertIn(f'id="{list_id}"', self.html)
            self.assertIn(f"querySelector('#{list_id}')", self.source,
                          msg=f"{list_id} must be keyboard-wired, not click-only")
        self.assertEqual(self.html.count('aria-selected="true"'), 2,
                         msg="Home and exactly one sub-tab start selected; the output "
                             "tablist is empty until a compile produces rules")
        self.assertIn('aria-controls=', self.html)
        self.assertIn("event.key === 'ArrowRight'", self.source,
                      msg="arrow-key navigation must be wired")

    def test_fields_the_api_requires_exist_and_are_sent(self):
        """currentFormConditions() must supply every field the API demands.

        A rebuild dropped `description` from that function, so /api/compile and
        /api/explain returned 400 on every keystroke-driven compile. The page still
        looked fine and the primary flow silently failed. This asserts the required
        API fields are both present in the form and referenced by the sender.
        """
        required = ("title", "description", "severity", "technique", "data_source",
                    "timeframe", "group_by", "threshold")
        for name in required:
            self.assertIn(f'name="{name}"', self.html,
                          msg=f"form is missing the required field {name}")
        sender = re.search(r"function currentFormConditions\(\)\s*\{(.*?)\n", self.source, re.DOTALL)
        self.assertIsNotNone(sender, msg="currentFormConditions() not found")
        body = sender.group(1)
        for name in required:
            if name in ("threshold", "description"):
                continue  # asserted separately: threshold by id, description by id due to the meta collision
            self.assertIn(f'"{name}"', body,
                          msg=f"currentFormConditions() does not send {name}; the API will reject it")
        self.assertIn("description:", body, msg="currentFormConditions() must send description")
        self.assertIn("#f-description", body,
                      msg="description must be read by id: <meta name=description> shadows [name=description]")

    def test_metadata_collision_detector_is_not_vacuous(self):
        """Guard the guard. This regex previously required `[` straight after `(` while
        every real call site is `querySelector('[name=...')`, so the optional quote never
        matched and the collision check below silently passed for the whole codebase while
        two live `document.querySelector('[name="description"]')` calls resolved to the
        <meta> tag instead of the textarea."""
        pattern = (r"querySelector(?:All)?\(\s*['\"]?\s*\[name=[\"']description[\"']\s*\]")
        self.assertRegex("document.querySelector('[name=\"description\"]')", pattern,
                         msg="detector must match the real call form, with the quote")
        self.assertNotRegex("document.querySelector('#f-description')", pattern,
                            msg="the id-based selector must not be flagged")
        # The source itself must be clean; the dedicated collision test below enforces it
        # over every colliding name. Asserting the bad pattern was PRESENT here would have
        # made this guard contradict its own purpose.
        self.assertEqual(re.findall(pattern, self.source), [],
                         msg="app.js still selects description by name; it resolves to <meta>")

    def test_form_field_names_do_not_collide_with_page_metadata(self):
        """A <meta name="description"> sits above the form, so `[name=description]`
        resolves to the meta tag and .value is undefined - which silently 400'd every
        compile. Any form field whose name is reused in page metadata must be addressed
        by id instead."""
        meta_names = set(re.findall(r"<meta[^>]*\sname=\"([^\"]+)\"", self.html))
        form_names = set(re.findall(r"<(?:input|select|textarea)\b[^>]*\sname=\"([^\"]+)\"", self.html))
        collisions = meta_names & form_names
        self.assertTrue(collisions, msg="extraction found nothing; the test would be vacuous")
        for name in collisions:
            # The sender must not select these by [name=...]; it must use an id.
            # The optional quote after "(" is load-bearing: without it this loop never
            # matched a single real call site and the test was vacuous.
            for match in re.finditer(
                    r"querySelector(?:All)?\(\s*['\"]?\s*\[name=[\"']" + re.escape(name) + r"[\"']\s*\]",
                    self.source):
                self.fail(f"app.js selects the form field by [name={name}], but <meta name={name}> "
                          "also matches and wins; address it by id instead")

    def test_header_counters_are_populated_on_load(self):
        """The header stats must not sit on em-dashes until another mode is opened."""
        self.assertIn("loadHeaderStats()", self.source)
        # loadHeaderStats must run at top level, not only from inside a tab handler.
        self.assertRegex(self.source, r"(?m)^loadHeaderStats\(\);",
                         msg="loadHeaderStats() must be invoked on page load")
        for stat in ("stat-techniques", "stat-mapped"):
            self.assertIn(f'id="{stat}"', self.html, msg=f"missing header stat {stat}")

    def test_output_panel_reports_the_compiled_target_count(self):
        """The Output panel claimed '0 targets' after a successful compile."""
        self.assertIn('id="output-count"', self.html)
        self.assertRegex(self.source, r"outputCount\.textContent\s*=",
                         msg="the compiled target count must be written back to the panel")

    def test_exactly_two_primary_tabs_centred_at_the_top(self):
        """The shell is Home + Rule Studio. Anything else re-creates the crowded rail."""
        primaries = re.findall(r'data-primary="([a-z]+)"', self.html)
        self.assertEqual(primaries, ["home", "studio"],
                         msg="there must be exactly two primary tabs, in order: home, studio")
        self.assertNotIn('class="rail', self.html,
                         msg="the side rail must be gone; its modes are sub-tabs now")
        for shell in ("view-home", "view-studio"):
            self.assertIn(f'id="{shell}"', self.html, msg=f"missing shell panel {shell}")
        self.assertEqual(self.html.count('class="shell active"'), 1,
                         msg="exactly one shell may be active on load")

    def test_studio_subtabs_sit_below_the_primary_tabs(self):
        """The modes row must be a sibling after the primary nav, not a side column."""
        self.assertLess(self.html.index('id="primary-tabs"'), self.html.index('id="sub-tabs"'),
                        msg="primary tabs must be served above the sub-tab row")
        modes = re.findall(r'class="sub-tab[^"]*" role="tab"[^>]*data-tab="([a-z]+)"', self.html)
        expected = ["compose", "import", "test", "attack", "coverage", "mappings", "history"]
        self.assertEqual(modes, expected,
                         msg="every former rail mode must survive as a Rule Studio sub-tab")
        panels = re.findall(r'class="view[^"]*" id="view-([a-z]+)"', self.html)
        for mode in modes:
            self.assertIn(mode, panels, msg=f"sub-tab {mode} has no panel")
        self.assertEqual(self.html.count('class="view active"'), 1,
                         msg="exactly one sub-view may be active on load")

    def test_nav_state_is_declared_before_the_init_calls_that_use_it(self):
        """A `let` declared beside its consumer is in its temporal dead zone at init.

        showPrimary() calls loadHome() during initialisation, and loadHome()'s re-entry
        guard was originally declared at the bottom of the file. That threw
        'Cannot access homeLoading before initialization', which aborted the remainder of
        the init sequence. The page still looked correct because the served markup already
        carried the active classes, so only the browser console exposed it.
        """
        init = self.source.index("showPrimary(primaryTabs.some")
        self.assertIn("showSubTab(subTabs.some", self.source,
                      msg="both init calls must run at top level")
        for name in ("homeLoading",):
            self.assertLess(self.source.index(f"let {name}"), init,
                            msg=f"'{name}' is used during init but declared after it")

    def test_complete_rule_is_the_primary_output_not_the_sections(self):
        """The rule was only ever shown as per-section boxes, so copying meant stitching
        fragments together by hand. The assembled text could differ from the real
        artifact. The API has always returned the complete `rule`; this pins that it is
        what the UI leads with, and that the section view is demoted to an inspector.
        """
        self.assertIn("rule-primary", self.source,
                      msg="the complete rule must be rendered as the primary box")
        self.assertIn("${escapeHtml(item.rule)}", self.source,
                      msg="the primary box must show item.rule verbatim")
        self.assertIn("Inspect rule sections", self.source,
                      msg="sections stay available, demoted to an inspector")
        self.assertIn("this is what you deploy", self.source,
                      msg="label the primary box so it is obvious which text to copy")
        # The old behaviour: section blocks open by default, i.e. the breakdown led.
        self.assertNotRegex(self.source, r'class="section-block" open',
                            msg="sections must not be expanded by default; they are secondary")

    def test_text_contrast_meets_its_target_in_both_themes(self):
        """Faded text was the single most-repeated usability complaint.

        --text-3 measured 3.60-5.11:1 on the dark surfaces, which fails WCAG AA (4.5:1)
        for normal text. This asserts a real ratio, not a colour string, so a later
        "tidy the palette" commit cannot silently regress legibility again.
        """
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        # Tiers must stay distinct, or the hierarchy is gone even if each one passes.
        for scope, primary_min, secondary_min, tertiary_min in (
            (":root", 12.0, 9.0, 7.0),        # dark: AAA target for tertiary
            ('[data-theme="light"]', 12.0, 7.0, 4.5),  # light: AA target for tertiary
        ):
            tokens = _tokens(styles, scope)
            for name in ("--text", "--text-2", "--text-3", "--surface", "--surface-2", "--surface-3"):
                self.assertIn(name, tokens, msg=f"{scope} is missing {name}")
            surfaces = [tokens["--surface"], tokens["--surface-2"], tokens["--surface-3"]]
            for token, minimum in (("--text", primary_min),
                                   ("--text-2", secondary_min),
                                   ("--text-3", tertiary_min)):
                worst = min(_contrast(tokens[token], surface) for surface in surfaces)
                self.assertGreaterEqual(
                    worst, minimum,
                    msg=(f"{scope} {token} ({tokens[token]}) reaches only "
                         f"{worst:.2f}:1 against the worst surface; needs >= {minimum}:1"))

    def test_home_dashboard_has_real_content_not_a_placeholder(self):
        """Home is a landing view, so its counters must be ids the script can fill."""
        for element_id in ("home-techniques", "home-buildable", "home-mapped",
                           "home-coverage", "home-history"):
            self.assertIn(f'id="{element_id}"', self.html, msg=f"missing home element {element_id}")
        self.assertIn("loadHome()", self.source)
        self.assertRegex(self.source, r"(?m)^loadHome\(\);",
                         msg="loadHome() must run on page load, not only on navigation")
        self.assertIn("class=\"hero\"", self.html)


    # ── Regressions for the seven functional defects found by UI sweep ──

    def test_threshold_reaches_the_generate_payload(self):
        """#threshold lives in the Test panel, OUTSIDE #rule-form.

        The submit handler built its payload from `new FormData(form)`, so the threshold
        was never sent, the backend silently defaulted to 1, and the compiled rule fired
        on a single event while the Test tab reported the tuned value. The stepper value
        must therefore be assigned explicitly.
        """
        self.assertNotIn("data.threshold", self.html, "guard the premise of this test")
        self.assertIn("data.threshold = thresholdValue", self.source,
                      msg="the submit handler must assign threshold explicitly")
        self.assertRegex(self.source, r"function readThreshold\(\)",
                         msg="one reader must own threshold validation")
        self.assertIn("readThreshold().value", self.source,
                      msg="currentFormConditions must use the same reader, or Test and "
                          "Compile can disagree again")
        self.assertIn("if (thresholdState.error) { showError(", self.source,
                      msg="an invalid typed threshold must be refused visibly, not clamped")

    def test_validation_errors_are_actually_visible(self):
        """#form-error ships with the `hidden` attribute.

        The handler only ever set `.textContent`, so every validation failure filled a
        box the analyst could not see and the UI looked inert. Any direct write that
        bypasses showError/clearError reintroduces the silent failure.
        """
        self.assertIn('id="form-error"', self.html)
        self.assertRegex(self.html, r'id="form-error"[^>]*\bhidden\b',
                         msg="guard the premise: the box must still ship hidden")
        self.assertIn("function showError(", self.source)
        self.assertIn("errorBox.hidden = false", self.source,
                      msg="showError must reveal the box")
        self.assertIn("function clearError(", self.source)
        self.assertIn("errorBox.hidden = true", self.source,
                      msg="clearError must re-hide it, or a stale error sticks")
        direct = [m for m in re.finditer(r"errorBox\.textContent\s*=", self.source)
                  if "function showError" not in self.source[max(0, m.start() - 200):m.start()]
                  and "function clearError" not in self.source[max(0, m.start() - 200):m.start()]]
        self.assertEqual([m.group(0) for m in direct], [],
                         msg="these writes bypass showError/clearError and stay invisible")

    def test_fixture_save_labels_events_before_posting(self):
        """storage.save_fixture rejects events with no `_expected` label.

        Labeling the shipped presets is NOT the fix: evaluator/match_tester.py scores
        TP/FP from `_expected`, so labeling them would silently change every Test
        verdict. The label must be requested at save time instead.
        """
        self.assertIn("parseEventText", self.source,
                      msg="fixtureEvents must reuse the shared parser")
        self.assertRegex(self.source, r"window\.confirm\([\s\S]{0,400}_expected",
                         msg="the analyst must confirm the should-fire assertion")
        self.assertIn("event._expected = true", self.source)
        self.assertRegex(self.source, r"if \(!proceed\)[\s\S]{0,300}return;",
                         msg="cancelling the confirm must abort the save, not assume a label")

    def test_event_parser_accepts_every_advertised_format(self):
        """The textarea is labelled JSON / NDJSON / CSV but only a JSON array worked.

        A single JSON object 400'd with 'Provide events: [{...}, ...].', which is the
        most natural paste and was one of the 400s in a real session log.
        """
        self.assertIn("function parseEventText(", self.source)
        self.assertIn("function splitCsvLine(", self.source,
                      msg="CSV must be split with quote handling, not a bare l.split(',')")
        body = re.search(r"function parseEventText\(([\s\S]*?)\n(?=[a-zA-Z])", self.source)
        self.assertIsNotNone(body, msg="could not isolate parseEventText")
        text = body.group(1)
        self.assertIn("return Array.isArray(parsed) ? parsed : [parsed]", text,
                      msg="a single JSON object must be wrapped, not rejected")
        self.assertRegex(text, r"lines\.every\(l => l\.startsWith\('\{'\)\)",
                         msg="NDJSON (one object per line) must be supported")
        self.assertIn("const header = splitCsvLine(", text,
                      msg="CSV header row must go through the quoting-aware splitter")
        self.assertIn("Number(v)", text, msg="CSV values must be coerced for matching")
        for guard in ("duplicate column names", "but the header declares"):
            self.assertIn(guard, text,
                          msg=f"CSV must reject {guard!r} rather than silently reshaping the data")

    def test_the_file_input_is_wired(self):
        """#ingest-file had no handler; Ingest only read the textarea, so it did nothing."""
        self.assertIn('id="ingest-file"', self.html)
        self.assertIn("'#ingest-file')", self.source,
                      msg="the file input must have a change handler")
        self.assertIn("readAsText", self.source, msg="the file must actually be read")
        self.assertIn("ndjson", self.source,
                      msg="the format should be inferred from the file extension")

    def test_buildable_attack_rows_are_real_buttons(self):
        """ATT&CK rows were divs with cursor:pointer and no handler.

        Clicking did nothing despite the UI promising a jump into a template, and they
        were unreachable by keyboard. Buildable techniques must be buttons; reference-only
        ones must stay inert so the grid does not promise clicks that do nothing.
        """
        self.assertIn('data-technique="${escapeHtml(t.templates[0])}"', self.source,
                      msg="the button must carry the INTERNAL template id, not the MITRE id")
        self.assertIn('data-mitre="${escapeHtml(t.id)}"', self.source,
                      msg="the MITRE id is kept separately, for display only")
        self.assertNotIn('data-technique="${escapeHtml(t.id)}"', self.source,
                         msg="passing the MITRE id makes the loaded form uncompilable")
        self.assertIn("showTab('compose')", self.source,
                      msg="clicking a buildable row must navigate to the composer")
        self.assertIn("dispatchEvent(new Event('change'", self.source,
                      msg="the composer must prefill from the chosen technique")
        self.assertIn('class="attack-row static"', self.source,
                      msg="reference-only rows must be explicitly inert")
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        self.assertIn("button.attack-row:hover", styles,
                      msg="only the interactive row may carry the hover affordance")
        self.assertIn(".attack-row.static", styles, msg="static rows need a rule too")

    def test_secondary_payloads_carry_the_form_switches(self):
        """currentFormConditions() dropped condition_logic/use_threshold/strict.

        Test, Explain, Compile, Evasion, Replay and Diff all use it, so selecting ANY or
        turning the threshold off was silently ignored by every one of them.
        """
        body = re.search(r"function currentFormConditions\(\)\s*\{(.*?)\n(?=[a-zA-Z])",
                         self.source, re.DOTALL)
        self.assertIsNotNone(body, msg="currentFormConditions() not found")
        text = body.group(1)
        for key in ("condition_logic", "use_threshold", "strict"):
            self.assertIn(f"{key}:", text,
                          msg=f"secondary payloads must send {key}; it is silently defaulted")


if __name__ == "__main__":
    unittest.main()
