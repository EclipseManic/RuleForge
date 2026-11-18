"""The rebuilt front end's contract with itself.

There is no DOM in this suite, so these tests protect the things that can be
checked from bytes on disk -- and those are exactly the things that rot
silently: a screen that is not wired, a colour that bypasses the token system, a
control the redesign quietly dropped, and a template that no longer parses.

The behavioural checks (a click produces the right request) live in the manual
acceptance run described in UI_REBUILD_PLAN.md; these are the floor that runs
with `python run.py verify`.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
TEMPLATES = WEB / "templates"
STATIC = WEB / "static"
JS = STATIC / "js"

SHELL = TEMPLATES / "index.html"
CLASSIC = TEMPLATES / "classic.html"
TOKENS = STATIC / "css" / "tokens.css"

SCREENS = [
    "home", "details", "source", "conditions", "stages", "preview",
    "test", "datasets", "receipts", "versions", "explain", "draft",
    "reference", "health",
]

#: The old ids that are deliberately gone. Four controls were replaced or
#: absorbed by the redesign; the rest are the chrome of the old single page
#: (its panes, its two-level tab bar and the decorative landing-page radios),
#: which no longer exists because every screen is a URL now.
RETIRED_IDS = {
    # the ten-way stage dropdown, replaced by the Stage library's cards
    "add-stage", "add-stage-kind",
    # the three run-and-save paths, collapsed into Receipts
    "run-save-evidence", "build-dataset", "build-expected",
    "build-evidence-status",
    # the old page chrome
    "tabs", "subtabs", "current-context",
    "pane-home", "pane-build", "pane-import", "pane-fromlog",
    "pane-datasets", "pane-testruns", "pane-history",
    "rf-d-sigma", "rf-d-splunk", "rf-d-sentinel", "rf-d-qradar",
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def all_js() -> str:
    return "".join(read(path) for path in sorted(JS.rglob("*.js")))


class Shell(unittest.TestCase):
    def test_the_shell_is_the_shell_and_nothing_else(self):
        shell = read(SHELL)
        for mount in ("id=\"mainnav\"", "id=\"subnav\"", "id=\"authorbar\"",
                      "id=\"screen\"", "id=\"problems\"",
                      "id=\"statusbar\"", "id=\"rulebar\"", "id=\"steps\""):
            self.assertIn(mount, shell)
        # No left rail: navigation is two rows at the top, and Author's steps
        # are inside the page. A sidebar made every tool look like a peer of
        # every step.
        self.assertNotIn('id="rail"', shell)
        self.assertNotIn("rail", read(STATIC / "css" / "components.css"))
        self.assertNotIn("refreshRail", all_js())
        # A shell that carries markup for a screen has gone back to being a
        # page with panes, which is what this rebuild was for.
        self.assertLess(len(shell.splitlines()), 140)

    def test_every_stylesheet_is_linked_in_order(self):
        shell = read(SHELL)
        order = ["tokens.css", "base.css", "components.css", "screens.css"]
        positions = [shell.index(name) for name in order]
        self.assertEqual(positions, sorted(positions))

    def test_the_shell_loads_the_entry_module(self):
        self.assertIn('type="module" src="/static/js/main.js"', read(SHELL))

    def test_the_old_interface_is_still_reachable(self):
        # Until parity is accepted, /classic must keep working: there is never
        # a moment where nothing works.
        self.assertTrue(CLASSIC.is_file())
        api = read(WEB / "api.py")
        self.assertIn('"/classic"', api)
        self.assertIn('_TEMPLATE_ROOT / "classic.html"', api)


class Wiring(unittest.TestCase):
    def test_every_screen_module_exists(self):
        for name in SCREENS:
            with self.subTest(screen=name):
                self.assertTrue((JS / "screens" / f"{name}.js").is_file())

    def test_every_screen_is_registered_in_main(self):
        main = read(JS / "main.js")
        for name in SCREENS:
            with self.subTest(screen=name):
                self.assertIn(f"import * as {name} from './screens/{name}.js'", main)
                self.assertIn(name, main)

    def test_the_router_knows_every_screen(self):
        router = read(JS / "core" / "router.js")
        for name in SCREENS:
            with self.subTest(screen=name):
                self.assertIn(f"name: '{name}'", router)

    def test_no_screen_reaches_for_the_dom_globally(self):
        """Controllers read state, never inputs.

        The old UI read its rule out of the DOM at the moment of each request,
        which is why a bug had no single place to be. A screen that calls
        `document.querySelector('#rule-id')` for a value would reintroduce it.
        """
        patterns = [
            r"document\.querySelector\('#an-(?:title|description|severity|author)'\)",
            r"document\.querySelector\('#rule-id'\)",
            r"document\.querySelector\('#read-(?:table|selector|timefield)'\)",
        ]
        for path in sorted((JS / "screens").glob("*.js")):
            source = read(path)
            for pattern in patterns:
                with self.subTest(file=path.name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, source))


class Styling(unittest.TestCase):
    def test_no_colour_lives_outside_the_token_file(self):
        token_text = read(TOKENS)
        hex_pattern = re.compile(r"#[0-9a-fA-F]{3,8}\b")
        self.assertTrue(hex_pattern.search(token_text),
                        "the token file should declare the palette")
        for path in sorted((STATIC / "css").glob("*.css")):
            if path == TOKENS:
                continue
            with self.subTest(file=path.name):
                self.assertIsNone(
                    hex_pattern.search(read(path)),
                    f"{path.name} declares a raw colour; use a token instead",
                )

    def test_every_token_used_is_defined(self):
        defined = set(re.findall(r"--[a-z0-9-]+", read(TOKENS)))
        used: set[str] = set()
        for path in sorted((STATIC / "css").glob("*.css")):
            used |= set(re.findall(r"var\((--[a-z0-9-]+)", read(path)))
        missing = sorted(used - defined - {"--x"})
        self.assertEqual(missing, [], f"undefined custom properties: {missing}")

    def test_there_is_only_one_token_block(self):
        # Selectors, not the word: the token file's own header explains why two
        # competing blocks were a problem, and that sentence mentions `:root`.
        self.assertEqual(len(re.findall(r"(?m)^:root\b", read(TOKENS))), 1)
        for path in sorted((STATIC / "css").glob("*.css")):
            if path == TOKENS:
                continue
            with self.subTest(file=path.name):
                self.assertIsNone(
                    re.search(r"(?m)^:root\b", read(path)),
                    f"{path.name} declares a second token block",
                )


class NoMarkupFromStrings(unittest.TestCase):
    def test_the_ui_builds_nodes_never_markup(self):
        """A rule title is user text. Building screens with innerHTML would put
        it in the document as markup. Every node is created with createElement."""
        # Usage, not mention: the rule is stated in prose in dom.js, and prose
        # must be allowed to name the thing it forbids.
        forbidden = [
            r"\.innerHTML\s*=",
            r"\binnerHTML\s*\+?=",
            r"\.outerHTML\s*=",
            r"insertAdjacentHTML\s*\(",
            r"document\.write\s*\(",
            r"new Function\s*\(",
        ]
        sources = list(JS.rglob("*.js"))
        self.assertTrue(sources)
        for path in sorted(sources):
            source = read(path)
            for pattern in forbidden:
                with self.subTest(file=path.name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, source))


class Reference(unittest.TestCase):
    def test_the_engine_notes_are_points_not_one_paragraph(self):
        """The per-dialect notes used to be joined with ' \u00b7 ' into a single
        footnote -- thousands of words in one block, which nobody reads. Each
        dialect is now a card and each sentence in its note is a point."""
        source = read(JS / "screens" / "reference.js")
        self.assertNotIn("'Caveats: '", source)
        self.assertIn("dialect-notes", source)
        self.assertIn("dialect-points", source)
        self.assertIn("pointsOf", source)
        styles = read(STATIC / "css" / "screens.css")
        self.assertIn(".dialect-notes {", styles)
        self.assertIn(".dialect-points li {", styles)


class Reading(unittest.TestCase):
    """Small, faint text is a defect, not a style. The floor is 12px for body
    copy and 11px for labels, with the muted grey at a contrast that survives a
    cheap laptop screen."""

    def setUp(self):
        self.css = {path.name: read(path)
                    for path in sorted((STATIC / "css").glob("*.css"))}

    def test_nothing_is_set_below_eleven_pixels(self):
        for name, source in self.css.items():
            for match in re.finditer(r"font-size:\s*([0-9.]+)px", source):
                with self.subTest(file=name, size=match.group(0)):
                    self.assertGreaterEqual(float(match.group(1)), 11.0)

    def test_body_copy_is_fifteen(self):
        self.assertRegex(self.css["base.css"], r"body\s*{[^}]*font-size:\s*15px")

    def test_the_muted_grey_is_legible_on_the_page(self):
        tokens = self.css["tokens.css"]
        muted = re.search(r"--text-muted:\s*#([0-9a-f]{6})", tokens).group(1)
        page = re.search(r"--surface-page:\s*#([0-9a-f]{6})", tokens).group(1)

        def luminance(hex_value):
            channels = [int(hex_value[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
                      for c in channels]
            return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

        lighter, darker = sorted((luminance(muted), luminance(page)), reverse=True)
        ratio = (lighter + 0.05) / (darker + 0.05)
        self.assertGreaterEqual(round(ratio, 2), 5.5,
                                "muted text should clear WCAG AA for body copy")

    def test_the_content_is_allowed_to_use_the_window(self):
        tokens = self.css["tokens.css"]
        limit = int(re.search(r"--content-max:\s*(\d+)px", tokens).group(1))
        self.assertGreaterEqual(limit, 1320)


class Migration(unittest.TestCase):
    def test_no_control_was_dropped_without_saying_so(self):
        old = set(re.findall(r'\bid="([a-z][a-z0-9-]*)"', read(CLASSIC)))
        new = read(SHELL) + all_js()
        missing = {
            name for name in old
            if f'"{name}"' not in new and f"'{name}'" not in new
        }
        self.assertEqual(
            sorted(missing - RETIRED_IDS), [],
            "these ids vanished from the old UI without being declared retired",
        )

    def test_the_retired_list_is_not_a_wish_list(self):
        """Every id declared retired must actually be gone, or the list stops
        being a record of what happened and becomes a place to hide things."""
        old = set(re.findall(r'\bid="([a-z][a-z0-9-]*)"', read(CLASSIC)))
        new = read(SHELL) + all_js()
        resurrected = sorted(
            name for name in RETIRED_IDS
            if name in old and (f'"{name}"' in new or f"'{name}'" in new)
        )
        self.assertEqual(resurrected, [])


class Templates(unittest.TestCase):
    def test_templates_are_parsed_by_the_engine_they_rely_on(self):
        """A template that no longer lowers is worse than no template."""
        from web.api import Api

        source = read(JS / "core" / "ir.js")
        block = source[source.index("export const TEMPLATES"):]
        dialect = re.findall(r"dialect: '([a-z]+)'", block)
        texts = re.findall(r"text: \[(.*?)\]\.join\('\\n'\)", block, re.S)
        self.assertEqual(len(dialect), 4)
        self.assertEqual(len(texts), 4)

        api = Api.__new__(Api)  # lowering needs no store
        for key, chunk in zip(dialect, texts):
            body = "\n".join(
                re.findall(r"'((?:[^'\\]|\\.)*)'", chunk)
            ).encode().decode("unicode_escape")
            with self.subTest(template=body.splitlines()[0]):
                lowered = api.lower({"dialect": key, "text": body})
                self.assertIn("rule", lowered)
                self.assertIn("pipeline", lowered["rule"]["rule"])


class Navigation(unittest.TestCase):
    """Two views at the top, tools in the second row, steps inside the page."""

    def setUp(self):
        self.router = read(JS / "core" / "router.js")
        self.shell = read(JS / "ui" / "shell.js")

    def test_home_and_studio_are_the_two_views(self):
        shell = read(SHELL)
        self.assertIn('data-nav="home"', shell)
        self.assertIn('data-nav="studio"', shell)

    def test_studio_tabs_are_the_tools(self):
        for label in ("Datasets", "Receipts", "Explain", "Draft from logs",
                      "History", "Reference", "Health"):
            with self.subTest(tool=label):
                self.assertIn(f"label: '{label}'", self.router)

    def test_the_six_steps_are_not_tabs(self):
        # Author is one tab. Its steps are reached from the step row and from
        # the Previous/Next buttons at the bottom of each screen.
        for step in ("Details", "Source", "Conditions", "Stage library",
                     "Preview", "Test"):
            with self.subTest(step=step):
                self.assertNotIn(f"{{ name: '{step.lower()}', label: '{step}', " + "path:",
                                 self.router)

    def test_every_step_has_a_previous_and_a_next(self):
        shared = read(JS / "screens" / "shared.js")
        self.assertIn("previousStepOf", shared)
        self.assertIn("nextStepOf", shared)
        for screen in ("details", "source", "conditions", "stages",
                       "preview", "test"):
            with self.subTest(screen=screen):
                self.assertIn(f"stepFooter('{screen}')",
                              read(JS / "screens" / f"{screen}.js"))

    def test_a_previous_url_still_resolves(self):
        # A bookmark, or a link from the previous build, must not land blank.
        self.assertIn("if (path[0] === 'rule')", self.router)
        self.assertIn("['start', 'home']", self.router)

    def test_the_two_views_sit_in_the_middle_of_the_bar(self):
        """Home / Studio is the middle column of a three-column bar, not a row
        of links trailing the logo. Equal 1fr sides are what centre it no matter
        how wide the controls on the right are."""
        components = read(STATIC / "css" / "components.css")
        topbar = components[components.index(".topbar {"):]
        topbar = topbar[:topbar.index("}")]
        self.assertIn("grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr)",
                      topbar)
        self.assertIn("justify-self: end", components)

    def test_both_directions_are_always_on_the_page(self):
        """The step footer never renders one button without the other: the
        first step shows a disabled Previous, the last step's Next is the save."""
        shared = read(JS / "screens" / "shared.js")
        footer = shared[shared.index("export function stepFooter"):]
        footer = footer[:footer.index("/* -- starting a rule")]
        self.assertIn("'prev-step'", footer)
        self.assertIn("'next-step'", footer)
        self.assertIn("disabled: !previous", footer)
        self.assertIn("#save-version", footer)
        self.assertNotIn("h('span', {})", footer)

    def test_the_jump_palette_is_gone(self):
        """It was a second way to do what the two bars already do, with a
        shortcut nobody asked for. Removed from the markup, the script and the
        stylesheet so it cannot come back by halves."""
        self.assertNotIn('id="palette"', read(SHELL))
        self.assertNotIn('id="jump"', read(SHELL))
        self.assertNotIn("openPalette", all_js())
        self.assertNotIn(".palette", read(STATIC / "css" / "components.css"))
        self.assertNotIn("palette", read(JS / "core" / "state.js"))


class FirstRun(unittest.TestCase):
    """The first thirty seconds, guarded from bytes.

    A rebuild is only better if a newcomer still lands somewhere with a way in.
    """

    def setUp(self):
        self.home = read(JS / "screens" / "home.js")
        self.main = read(JS / "main.js")
        self.router = read(JS / "core" / "router.js")

    def test_the_app_opens_on_home(self):
        self.assertIn("if (!window.location.hash) window.location.hash = '#/'", self.main)
        self.assertIn("if (!path.length || path[0] === 'home') return { name: 'home', view: 'home', query };",
                      self.router)

    def test_a_fresh_session_opens_with_a_real_rule(self):
        # An empty rule on the home page would advertise a blank query as the
        # first thing anyone sees.
        self.assertIn("if (!restored) seedExample();", self.main)
        self.assertIn("loadRule({", self.main)

    def test_the_shell_has_no_panes(self):
        # Panes are the shape of the old single page: one document with every
        # screen in it, only one visible. A screen is a route now.
        shell = read(SHELL)
        self.assertNotIn('class="pane', shell)
        self.assertNotIn("data-pane", shell)

    def test_home_offers_a_worked_example_and_a_blank_rule(self):
        self.assertIn("'home-example'", self.home)
        self.assertIn("id: 'home-blank'", self.home)
        self.assertIn("emptyRule()", all_js())

    def test_home_names_the_dialects_from_the_api(self):
        # Named from /api/dialects, so the landing copy cannot claim a count
        # that has gone stale.
        self.assertIn("id: 'home-dialects'", self.home)
        self.assertIn("state.cache.dialects", self.home)

    def test_home_shows_the_rule_that_is_actually_loaded(self):
        self.assertIn("'/api/render'", read(JS / "core" / "api.js"))
        self.assertIn("api.render(target, state.doc.payload)", self.home)

    def test_home_offers_the_four_workflows(self):
        for screen in ("details", "test", "datasets", "explain"):
            with self.subTest(door=screen):
                self.assertIn(f"to: '{screen}'", self.home)

    def test_there_is_exactly_one_place_a_run_is_saved(self):
        receipts = read(JS / "screens" / "receipts.js")
        self.assertIn("id: 'test-run-save'", receipts)
        self.assertIn("'/api/test-runs'", read(JS / "core" / "api.js"))
        # The three competing run buttons of the old builder are gone.
        self.assertNotIn("run-save-evidence", read(SHELL) + all_js())
        # One caller. The definition is an arrow const, not a call.
        self.assertEqual(all_js().count("saveRun("), 1)


if __name__ == "__main__":
    unittest.main()
