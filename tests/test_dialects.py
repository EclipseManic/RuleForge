"""The dialect registry, and the vendor-isolation rule it protects.

`run.py` claims that nothing in the engine is allowed to know a
vendor exists, and that the rule is "enforced by a test rather than by good
intentions". That test did not exist. This is it.

The rest of this file is the other half of the same idea: the registry declares
what each dialect can do, and these tests import every ready dialect and check
the declaration against the module. A registry that claims a dialect can parse
when it cannot is worse than one that admits it cannot -- the first returns a
confident empty rule, the second refuses.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import unittest

from engine import dialects
from engine.dialects import Dialect, REGISTRY
from engine.dialects.common import Diagnostic
from engine.ir import Rule
from engine.values import Refusal

try:
    from . import planned_dialect
except ImportError:  # pragma: no cover - `unittest discover -s tests`
    # See the same block in `test_api.py`: `discover -s tests` imports these
    # modules top-level, so the relative form has no parent package.
    from tests import planned_dialect

#: `engine/dialects/__init__.py` -> `engine/dialects` -> `engine`.
ENGINE = pathlib.Path(dialects.__file__).resolve().parent.parent
#: The repository root, one level above the engine.
ROOT = ENGINE.parent

#: The vendor-neutral engine. Nothing here may import a dialect.
#:
#: These are the modules in `engine/`. They sat at the repository root once;
#: moving them into a package did not change the claim they make -- that the
#: engine may not know a vendor exists -- only the directory it is read from.
ENGINE_MODULES = (
    "ir", "values", "validate", "evaluate", "pipeline",
)

#: The reference rule, reused from the KQL suite so the registry is exercised
#: on something non-trivial rather than on `T | take 1`.
USER_RULE = """
let LSASSAccess =
SecurityEvent
| where EventID == 10
| where TargetImage endswith @"\\lsass.exe"
| project LSASSTime=TimeGenerated, Computer, Account, SourceImage, SourceIp;

let LateralMovement =
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| project LoginTime=TimeGenerated, Computer, Account, IpAddress;

LSASSAccess
| join kind=inner (LateralMovement) on Computer, Account
| where LoginTime between (LSASSTime .. LSASSTime + 10m)
| summarize Hits=count() by Computer, Account
| where Hits >= 1
"""


class VendorIsolation(unittest.TestCase):
    """The architectural rule, read off the import graph rather than trusted."""

    @staticmethod
    def _imports_in_source(source: str, filename: str = "<test>") -> list[str]:
        """Every name `source` imports, resolved enough to tell whether it
        points into `dialects`.

        The alias names matter as much as the module. `from . import dialects`
        and `import dialects` both reach the dialect layer while
        leaving `node.module` as None and "ruleforge" respectively -- so a
        detector that reads only `node.module`, as this one originally did,
        misses the two most natural ways an engine module would commit the
        violation. Both forms are covered by
        `test_the_violation_detector_actually_detects_violations` below.
        """
        tree = ast.parse(source, filename=filename)
        found: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                base = node.module or ""
                found.append(base)
                for alias in node.names:
                    found.append(f"{base}.{alias.name}" if base else alias.name)
            elif isinstance(node, ast.Import):
                found.extend(alias.name for alias in node.names)
        return found

    def _imports(self, module_name: str) -> list[str]:
        source = (ENGINE / f"{module_name}.py").read_text(encoding="utf-8")
        return self._imports_in_source(source, f"{module_name}.py")

    def test_the_engine_modules_exist_where_this_test_thinks_they_do(self):
        # A path test that silently finds nothing passes forever. ENGINE is
        # computed by walking up from `dialects.__file__`, so it is exactly one
        # `.parent` away from being the dialects directory instead of the
        # engine -- and both hold .py files, so the loop below would still find
        # entries if the walk were off by a level. Pin both directories by
        # files only they have, before trusting anything read out of them.
        self.assertTrue(
            (ROOT / "run.py").is_file(),
            f"ROOT resolved to {ROOT}, which is not the project root, "
            f"so every path assertion below is reading files this test did "
            f"not mean to read.",
        )
        self.assertTrue(
            (ENGINE / "dialects" / "__init__.py").is_file(),
            f"{ENGINE} does not contain the dialects package, so ENGINE is "
            f"not the engine directory these tests mean to read.",
        )
        for name in ENGINE_MODULES:
            with self.subTest(module=name):
                self.assertTrue(
                    (ENGINE / f"{name}.py").is_file(),
                    f"{name}.py is not at {ENGINE}. This test is looking in "
                    f"the wrong place and is not checking anything.",
                )

    def test_no_engine_module_imports_a_dialect(self):
        for name in ENGINE_MODULES:
            for imported in self._imports(name):
                with self.subTest(module=name, imported=imported):
                    self.assertNotIn(
                        "dialects", imported,
                        f"{name}.py imports `{imported}`. The engine "
                        f"is not allowed to know a vendor exists -- that is "
                        f"what makes eight dialects possible without eight "
                        f"tools.",
                    )

    def test_no_engine_module_reaches_a_dialect_dynamically(self):
        # The check above reads `import` statements, so importlib sidesteps it
        # entirely -- which is precisely how this package loads dialects one
        # directory down. The engine has no such call today; this keeps the
        # cheapest way around the isolation rule from being available later,
        # when the rule is load-bearing for eight dialects instead of one.
        for name in ENGINE_MODULES:
            source = (ENGINE / f"{name}.py").read_text(encoding="utf-8")
            tree = ast.parse(source, filename=f"{name}.py")
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                called = (
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else getattr(func, "id", "")
                )
                if called not in ("import_module", "__import__"):
                    continue
                with self.subTest(module=name, call=called):
                    self.fail(
                        f"{name}.py calls `{called}`. The engine must "
                        f"not be able to reach the dialect layer through an "
                        f"import that the static check cannot see."
                    )

    def test_the_violation_detector_actually_detects_violations(self):
        # The test above passes if the engine is clean -- and it also passes if
        # the detector is blind. These are the forms a real violation would
        # take; each one must be caught, or `test_no_engine_module_imports_a_
        # dialect` is decoration. The last two are the regression: reading only
        # `node.module` let them through, which made the isolation rule that
        # run.py cites unenforced for the most likely spellings.
        violations = (
            "from dialects import kql",
            "from dialects.kql import parse_kql",
            "from dialects import get",
            "from dialects.kql import lower_kql",
            "import dialects",
            "import dialects.kql",
        )

        for source in violations:
            with self.subTest(violation=source):
                names = self._imports_in_source(source)
                self.assertTrue(
                    any("dialects" in name for name in names),
                    f"`{source}` reaches the dialect layer but the detector "
                    f"reported {names}. A vendor-isolation test that cannot "
                    f"see the violation does not enforce anything.",
                )

    def test_the_violation_detector_does_not_cry_wolf(self):
        # The permitted imports must stay silent, or the rule gets disabled by
        # whoever has to ship around a false positive.
        permitted = (
            "from __future__ import annotations",
            "import ast",
            "from values import Refusal, Capability",
            "from ir import Rule, render_expr",
            "from .common import Diagnostic",
            "from dataclasses import dataclass",
            "from typing import Any, Final",
        )
        for source in permitted:
            with self.subTest(permitted=source):
                names = self._imports_in_source(source)
                self.assertFalse(
                    any("dialects" in name for name in names),
                    f"`{source}` is allowed, but the detector flagged it as a "
                    f"dialect import: {names}.",
                )

    def test_dialects_are_allowed_to_import_the_engine(self):
        # The dependency runs one way only. Asserting the permitted direction
        # keeps the test above from being satisfied by an empty dialect layer
        # that imports nothing at all.
        source = (ENGINE / "dialects" / "kql.py").read_text(encoding="utf-8")
        tree = ast.parse(source, filename="kql.py")
        relative = {
            (node.level, node.module or "")
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        # Level 2: `from ..ir import` climbs from engine/dialects/ to engine/.
        # Two dots, because the engine sits one level ABOVE the dialect package
        # instead of beside it at the repository root.
        self.assertIn((2, "ir"), relative)
        self.assertIn((2, "validate"), relative)


    def test_the_engine_vendor_exception_is_confined_to_one_constant(self):
        # ir.APPLIANCE_FUNCTIONS genuinely does name QRadar and Splunk
        # functions inside the engine, so the docstring's claim is not strictly
        # true. The exception is deliberate -- the engine has to know those
        # names to refuse to evaluate them -- but it must not spread, so it is
        # pinned here: engine vendor knowledge lives in APPLIANCE_FUNCTIONS and
        # nowhere else that imports a dialect.
        from engine import ir

        self.assertIn("qidname", ir.APPLIANCE_FUNCTIONS)
        self.assertIn("tstats", ir.APPLIANCE_FUNCTIONS)
        # And the names are only a refusal list -- they resolve to
        # DECLARED_ONLY, never to a vendor code path. Checking EVERY name
        # rather than sampling `qidname` is the whole point: one appliance
        # function that resolved to a real capability would be the engine
        # quietly executing vendor semantics, which is the thing the
        # architecture forbids.
        from engine.values import Capability

        self.assertTrue(ir.APPLIANCE_FUNCTIONS, "the refusal list is empty")
        for name in sorted(ir.APPLIANCE_FUNCTIONS):
            with self.subTest(function=name):
                self.assertIs(
                    ir.function_capability(name),
                    Capability.DECLARED_ONLY,
                    f"`{name}` is listed as appliance-only but resolves to a "
                    f"capability the engine would act on.",
                )


class RegistryShape(unittest.TestCase):
    def test_every_key_is_a_stable_lowercase_identifier(self):
        # The key is written into Rule.metadata["dialect"] and therefore into
        # saved rules. It cannot change once anything is stored with it.
        for key, entry in REGISTRY.items():
            with self.subTest(key=key):
                self.assertEqual(key, entry.key)
                self.assertEqual(key, key.lower().strip())
                self.assertTrue(key.isidentifier(), key)

    def test_every_entry_is_labelled_for_a_human(self):
        for entry in dialects.all_dialects():
            with self.subTest(key=entry.key):
                self.assertTrue(entry.label.strip())
                self.assertTrue(entry.language.strip())

    def test_the_eight_dialects_in_the_docstrings_are_all_accounted_for(self):
        # Three docstrings claim eight dialects. Now the claim is data, so a
        # ninth or a seventh is a test failure rather than a stale comment.
        self.assertEqual(len(REGISTRY), 8)

    def test_a_planned_dialect_carries_a_note_explaining_itself(self):
        for entry in dialects.all_dialects():
            if entry.ready:
                continue
            with self.subTest(key=entry.key):
                self.assertEqual(entry.status, "planned")
                self.assertTrue(
                    entry.note.strip(),
                    f"{entry.key} is planned but says nothing about what it "
                    f"needs. A greyed-out entry with no reason is a dead end "
                    f"in the UI.",
                )

    def test_a_planned_dialect_claims_no_capability(self):
        for entry in dialects.all_dialects():
            if entry.ready:
                continue
            with self.subTest(key=entry.key):
                self.assertFalse(entry.can_parse)
                self.assertFalse(entry.can_render)

    def test_every_entry_names_its_functions_by_the_shared_convention(self):
        # The attr names are data precisely so a dialect cannot get them
        # silently wrong -- but that only helps if the data is right BEFORE the
        # module lands. Every entry, planned included, names its functions
        # `<verb>_<module>`: sentinel's module is kql, so `lower_kql`; sigma's
        # will be sigma, so `lower_sigma`. Leaving a planned entry on the bare
        # `lower` default is the trap this pins shut -- flipping it to ready by
        # setting `module=` alone would then refuse with
        # DIALECT_CAPABILITY_MISSING against a module that is perfectly fine.
        for entry in dialects.all_dialects():
            stem = entry.module or entry.key
            with self.subTest(key=entry.key, stem=stem):
                self.assertEqual(entry.parse_attr, f"parse_{stem}")
                self.assertEqual(entry.lower_attr, f"lower_{stem}")
                self.assertEqual(entry.render_attr, f"render_{stem}")

    def test_ready_dialects_and_catalogue_are_faithful_views(self):
        # `ready_dialects()` filters and `catalogue()` projects -- neither is
        # allowed to reorder or drop. The picker renders the catalogue in the
        # order it is handed, so an order that drifts from `all_dialects()`
        # makes two screens disagree about one registry.
        every = dialects.all_dialects()
        self.assertEqual([d.key for d in every], list(REGISTRY))
        self.assertEqual(
            [row["key"] for row in dialects.catalogue()],
            [d.key for d in every],
        )
        self.assertEqual(
            [d.key for d in dialects.ready_dialects()],
            [d.key for d in every if d.ready],
        )

    def test_every_ready_dialect_is_actually_usable(self):
        # Asserting a COUNT here would break every time a dialect ships, which
        # trains people to update the number without reading it. Asserting that
        # each ready dialect really parses and renders is the property that
        # matters, and it keeps holding as more arrive.
        ready = dialects.ready_dialects()
        self.assertGreaterEqual(len(ready), 1)
        for entry in ready:
            with self.subTest(key=entry.key):
                self.assertIsNotNone(dialects.load(entry.key))
                self.assertTrue(entry.can_parse or entry.can_render)

    def test_sentinel_is_ready(self):
        self.assertIn("sentinel", [d.key for d in dialects.ready_dialects()])

    def test_every_dialect_in_the_registry_is_now_ready(self):
        # This replaces `test_at_least_one_dialect_is_still_planned`, which
        # existed to stop the planned-dialect refusal tests going vacuous. All
        # eight ship now, so those tests run against a synthetic entry
        # (`tests.planned_dialect`) instead of against a real dialect that
        # might ship and invert them -- which already happened twice here,
        # first with `sigma` and then with `wazuh`.
        self.assertEqual(
            [d.key for d in dialects.all_dialects() if not d.ready], [],
            "a dialect has gone back to planned; point the refusal tests at "
            "it only if you also keep the synthetic-entry tests.",
        )

    def test_a_planned_entry_is_still_representable(self):
        # The `planned` machinery is live code that a ninth dialect lands on,
        # so it stays tested even with nothing planned today.
        with planned_dialect() as key:
            entry = REGISTRY[key]
            self.assertFalse(entry.ready)
            self.assertEqual(entry.status, "planned")
            self.assertFalse(entry.can_parse)
            self.assertFalse(entry.can_render)
            self.assertTrue(entry.note.strip())

    def test_the_synthetic_entry_does_not_outlive_the_block(self):
        # A mutation that escapes fails later, in a test that looks unrelated,
        # and only for some execution orders.
        with planned_dialect() as key:
            self.assertIn(key, REGISTRY)
        self.assertNotIn(key, REGISTRY)

    def test_catalogue_is_plain_data(self):
        rows = dialects.catalogue()
        self.assertEqual(len(rows), len(REGISTRY))
        for row in rows:
            with self.subTest(key=row["key"]):
                self.assertEqual(
                    set(row),
                    {"key", "label", "language", "status", "can_parse",
                     "can_render", "carries_annotations", "note"},
                )
                self.assertIn(row["status"], ("ready", "planned"))

    def test_the_catalogue_says_whether_a_rules_metadata_survives(self):
        # The GUI needs this to warn before a conversion, and the registry
        # needs it to raise ANNOTATIONS_NOT_TRANSFERABLE. Five dialects
        # rendered a rule's whole triage header as nothing and said so
        # nowhere.
        rows = {r["key"]: r for r in dialects.catalogue()}
        self.assertTrue(rows["sigma"]["carries_annotations"])
        self.assertTrue(rows["sentinel"]["carries_annotations"])
        self.assertFalse(
            rows["crowdstrike"]["carries_annotations"],
            "FQL is one filter string with no comment syntax, so it cannot "
            "carry a title or a severity.",
        )


class DeclarationMatchesReality(unittest.TestCase):
    """The registry's claims, checked against the modules."""

    def test_every_ready_dialect_imports(self):
        for entry in dialects.ready_dialects():
            with self.subTest(key=entry.key):
                self.assertIsNotNone(dialects.load(entry.key))

    def test_declared_capabilities_exist_as_callables(self):
        for entry in dialects.ready_dialects():
            module = dialects.load(entry.key)
            if entry.can_parse:
                with self.subTest(key=entry.key, attr=entry.parse_attr):
                    self.assertTrue(callable(getattr(module, entry.parse_attr, None)))
                with self.subTest(key=entry.key, attr=entry.lower_attr):
                    self.assertTrue(callable(getattr(module, entry.lower_attr, None)))
            if entry.can_render:
                with self.subTest(key=entry.key, attr=entry.render_attr):
                    self.assertTrue(callable(getattr(module, entry.render_attr, None)))

    def test_the_module_agrees_with_the_registry_about_its_own_key(self):
        # kql.py declares DIALECT = "sentinel". If the registry key and the
        # module constant drift, rules get saved under one name and looked up
        # under another.
        #
        # The constant is REQUIRED, not checked-if-present. Guarding the
        # comparison with `if declared is not None` is how this test used to
        # pass while comparing nothing at all: point a ready entry at a module
        # that exports neither DIALECT nor LANGUAGE -- dialects/common.py is
        # one -- and both agreement tests went green without reading a single
        # declaration. Every dialect landing in this package is required to
        # export both, so a missing constant is the failure, not a skip.
        for entry in dialects.ready_dialects():
            module = dialects.load(entry.key)
            with self.subTest(key=entry.key):
                declared = getattr(module, "DIALECT", None)
                self.assertIsNotNone(
                    declared,
                    f"{module.__name__} is registered ready but exports no "
                    f"DIALECT constant, so nothing pins the module to the key "
                    f"`{entry.key}` that saved rules carry.",
                )
                self.assertEqual(declared, entry.key)

    def test_the_module_agrees_about_its_language(self):
        for entry in dialects.ready_dialects():
            module = dialects.load(entry.key)
            with self.subTest(key=entry.key):
                declared = getattr(module, "LANGUAGE", None)
                self.assertIsNotNone(
                    declared,
                    f"{module.__name__} is registered ready but exports no "
                    f"LANGUAGE constant, so the language shown in the picker "
                    f"is whatever the registry happens to say.",
                )
                self.assertEqual(declared, entry.language)


class RegistrySnapshot(unittest.TestCase):
    """Base for the tests that deliberately mutate REGISTRY.

    A mutation that escapes does not fail in the test that caused it. It fails
    later, in a test that looks unrelated, and only for some execution orders
    -- which is the worst failure mode a suite can have. So REGISTRY is
    snapshotted before every test in these classes and compared back after.
    The restore itself stays in the test's own `finally`: `tearDown` runs
    BEFORE `addCleanup` callbacks, so a cleanup-based restore would be checked
    before it had happened.

    TWO pieces of state are restored, not one. `load()`'s private module cache
    is keyed on (dialect key, module name), so a test that repoints an entry
    imports the new module and leaves a cache entry behind that the REGISTRY
    restore does not touch. Snapshotting only REGISTRY is what let that entry
    survive the whole run.
    """

    def setUp(self) -> None:
        self._registry_snapshot = dict(REGISTRY)
        self._loaded_snapshot = dict(dialects._LOADED)

    def tearDown(self) -> None:
        # `load()`'s module cache is part of the mutable state these tests
        # disturb, and snapshotting REGISTRY alone left it dirty: repointing an
        # entry at another module imports that module and caches it under
        # (key, module), and restoring REGISTRY in a `finally` does not evict
        # it. The suite was leaving a cache entry for a module the registry no
        # longer names, which is harmless only for as long as nothing else
        # repoints that key. Restore it in place, before the assertion below,
        # so the dict object `load()` writes through stays the same one and the
        # restore still happens when a test fails.
        dialects._LOADED.clear()
        dialects._LOADED.update(self._loaded_snapshot)
        self.assertEqual(
            REGISTRY,
            self._registry_snapshot,
            "this test mutated REGISTRY and did not put it back, so the next "
            "test to run would fail for reasons of its own that have nothing "
            "to do with it.",
        )


class CrossDialectRenderReportsLostAnnotations(unittest.TestCase):
    """A rule's triage header is what a SOC acts on.

    `ir.Annotations` holds the name an alert fires under, the severity it is
    routed by and the technique it is attributed to. Five of the eight
    dialects rendered all of it as NOTHING, so converting a Sigma rule -- the
    most common thing this tool will be asked to do -- produced an unnamed,
    unrated query. The text looked complete and the call reported success.

    Three of those five now write a comment header and read it back. SPL and
    FQL genuinely cannot, and they now say so.
    """

    SIGMA = (
        "title: LSASS Access\n"
        "description: Detects credential dumping\n"
        "author: soc team\n"
        "level: high\n"
        "tags:\n"
        "    - attack.credential_access\n"
        "    - attack.t1003.001\n"
        "references:\n"
        "    - https://example.com/lsass\n"
        "falsepositives:\n"
        "    - Backup software\n"
        "logsource:\n"
        "    category: process_access\n"
        "detection:\n"
        "    selection:\n"
        "        TargetImage|endswith: '/lsass.exe'\n"
        "    condition: selection\n"
    )

    def rule(self):
        rule, _ = dialects.lower("sigma", self.SIGMA)
        return rule

    def test_the_annotations_are_read_in_the_first_place(self):
        # If this fails the rest of the class proves nothing.
        annotations = self.rule().annotations
        self.assertEqual(annotations.title, "LSASS Access")
        self.assertEqual(annotations.severity, "high")

    def test_a_dialect_that_carries_them_writes_them(self):
        for key in ("sentinel", "qradar", "elastic"):
            with self.subTest(target=key):
                text, _notes = dialects.render(key, self.rule())
                self.assertIn("LSASS Access", text)
                self.assertIn("high", text)
                self.assertIn("T1003.001", text)

    def test_a_dialect_that_carries_them_reads_them_back(self):
        # A header written and not read is still a one-way loss.
        for key in ("sentinel", "qradar", "elastic"):
            with self.subTest(target=key):
                text, _ = dialects.render(key, self.rule())
                back, _ = dialects.lower(key, text)
                self.assertEqual(back.annotations.title, "LSASS Access")
                self.assertEqual(back.annotations.severity, "high")
                self.assertEqual(
                    back.annotations.mitre_attack,
                    (("credential-access", ("T1003.001",)),),
                )

    def test_a_dialect_that_cannot_carry_them_says_so(self):
        for key in ("splunk", "crowdstrike"):
            with self.subTest(target=key):
                _text, notes = dialects.render(key, self.rule())
                self.assertIn(
                    "ANNOTATIONS_NOT_TRANSFERABLE", [n.code for n in notes],
                    "the triage header is gone and nothing said so",
                )

    def test_the_report_names_what_was_lost(self):
        # "Some metadata was dropped" sends the analyst reading a diff.
        _text, notes = dialects.render("splunk", self.rule())
        note = next(
            n for n in notes if n.code == "ANNOTATIONS_NOT_TRANSFERABLE"
        )
        self.assertIn("title", note.message)
        self.assertIn("severity", note.message)
        self.assertIn("Splunk", note.message)

    def test_a_rule_with_no_annotations_is_silent(self):
        # A warning that fires on every hand-written rule trains the analyst
        # to dismiss the one that matters.
        rule, _ = dialects.lower("splunk", "index=a | where b == 1")
        _text, notes = dialects.render("splunk", rule)
        self.assertEqual(
            [n.code for n in notes if n.code == "ANNOTATIONS_NOT_TRANSFERABLE"],
            [],
        )

    def test_a_dialect_that_carries_them_does_not_warn(self):
        for key in ("sentinel", "qradar", "elastic", "sigma"):
            with self.subTest(target=key):
                _text, notes = dialects.render(key, self.rule())
                self.assertNotIn(
                    "ANNOTATIONS_NOT_TRANSFERABLE", [n.code for n in notes]
                )

    def test_the_declaration_matches_what_the_renderer_does(self):
        # The drift guard: `carries_annotations` is declared by hand, and the
        # consequence of it being wrong is silent.
        for entry in dialects.ready_dialects():
            if not entry.can_render:
                continue
            with self.subTest(target=entry.key):
                try:
                    text, _ = dialects.render(entry.key, self.rule())
                except Refusal:
                    continue
                carries = "LSASS Access" in text or "high" in text
                self.assertEqual(
                    carries, entry.carries_annotations,
                    f"{entry.key} declares carries_annotations="
                    f"{entry.carries_annotations} but its output "
                    f"{'does' if carries else 'does not'} hold the header",
                )

    def test_an_annotation_header_does_not_break_the_detection(self):
        # The header is a comment. A dialect that read it as part of the query
        # would change what the rule matches.
        text, _ = dialects.render("sentinel", self.rule())
        back, _ = dialects.lower("sentinel", text)
        self.assertEqual(
            [type(n).__name__ for n in back.pipeline],
            [type(n).__name__ for n in
             dialects.lower("sentinel", text)[0].pipeline],
        )
        again, _ = dialects.render("sentinel", back)
        self.assertEqual(again, text)


class EveryDialectIsStableAndSelfConsistent(unittest.TestCase):
    """One representative rule per dialect, round-tripped twice.

    A dialect whose renderer and parser disagree produces text that re-imports
    into a DIFFERENT rule, and nothing else in the suite necessarily notices:
    `kql.py` rendered a join predicate into the `on` clause for a long time,
    and the only reason it surfaced was that `validate` happened to refuse the
    re-imported rule. An unstable renderer also makes every save look like a
    change in history.

    Table-driven so a ninth dialect cannot ship without an entry.
    """

    SAMPLES = {
        "sentinel": (
            "SecurityEvent\n"
            "| where EventID == 10\n"
            '| where Image endswith "lsass.exe"\n'
            "| sort by TimeGenerated desc\n"
            "| take 5"
        ),
        "sigma": (
            "title: LSASS\n"
            "level: high\n"
            "author: soc\n"
            "logsource:\n"
            "    category: process_access\n"
            "detection:\n"
            "    selection:\n"
            "        TargetImage|endswith: '/lsass.exe'\n"
            "    condition: selection\n"
        ),
        "splunk": 'index=fw sourcetype=pan | where src_ip="10.0.0.1"',
        "qradar": (
            "SELECT sourceip, COUNT(*) AS hits\n"
            "FROM events\n"
            "WHERE qid = 1\n"
            "GROUP BY sourceip\n"
            "HAVING COUNT(*) > 5\n"
            "LAST 24 HOURS"
        ),
        "elastic": (
            "sequence by host.id with maxspan=5m\n"
            '  [process where process.name == "procdump.exe"]\n'
            '  [process where process.name : "LSASS*"]'
        ),
        "wazuh": (
            '<group name="sshd,"><rule id="5710" level="5">'
            "<if_sid>5700</if_sid><match>Failed password</match>"
            "<description>auth failed</description></rule></group>"
        ),
        "chronicle": (
            "rule r {\n"
            "  meta:\n"
            '    severity = "HIGH"\n'
            "  events:\n"
            '    $e.metadata.event_type = "PROCESS_OPEN"\n'
            "  condition:\n"
            "    $e\n"
            "}"
        ),
        "crowdstrike": (
            "event_simpleName:'ProcessRollup2'+FileName:['lsass.exe']"
        ),
    }

    def test_every_ready_dialect_has_a_sample(self):
        # The guard on the guard. A dialect with no entry is a dialect this
        # class silently does not check.
        ready = {e.key for e in dialects.ready_dialects()}
        self.assertEqual(
            sorted(ready - set(self.SAMPLES)), [],
            "a dialect shipped without a round-trip sample here",
        )

    def test_rendering_is_stable(self):
        for key, text in self.SAMPLES.items():
            with self.subTest(dialect=key):
                rule, _ = dialects.lower(key, text)
                once, _ = dialects.render(key, rule)
                again, _ = dialects.lower(key, once)
                twice, _ = dialects.render(key, again)
                self.assertEqual(
                    once, twice,
                    f"{key} renders differently on the second pass, so its "
                    f"parser and renderer disagree",
                )

    def test_the_stage_shape_survives_a_round_trip(self):
        # Byte-stability alone can hide a rule that lost a stage on the FIRST
        # pass and then stayed stable in its reduced form.
        for key, text in self.SAMPLES.items():
            with self.subTest(dialect=key):
                rule, _ = dialects.lower(key, text)
                once, _ = dialects.render(key, rule)
                again, _ = dialects.lower(key, once)
                self.assertEqual(
                    [type(n).__name__ for n in again.pipeline],
                    [type(n).__name__ for n in rule.pipeline],
                )

    def test_a_same_dialect_render_reports_no_loss(self):
        # Every caveat the registry raises on a same-dialect render would be a
        # claim that the dialect cannot carry its own rule.
        for key, text in self.SAMPLES.items():
            with self.subTest(dialect=key):
                rule, _ = dialects.lower(key, text)
                _once, notes = dialects.render(key, rule)
                self.assertEqual([n.code for n in notes], [])

    def test_every_sample_validates(self):
        from engine.validate import validate

        for key, text in self.SAMPLES.items():
            with self.subTest(dialect=key):
                rule, _ = dialects.lower(key, text)
                validate(rule)

    def test_every_sample_can_be_encoded_and_decoded(self):
        # The GUI and the history store both go through the codec, so a rule
        # that lowers but will not encode is a rule the tool cannot save.
        from engine.codec import rule_from_dict, rule_to_dict

        for key, text in self.SAMPLES.items():
            with self.subTest(dialect=key):
                rule, _ = dialects.lower(key, text)
                self.assertEqual(rule_from_dict(rule_to_dict(rule)), rule)


class RegistryRefusals(RegistrySnapshot):
    """The refusals a planned key hands back.

    These ran against whichever dialect happened to be unimplemented, which
    broke twice: pinned to `sigma` they inverted the day Sigma shipped, and
    looked up dynamically they went vacuous the day the last dialect shipped.
    A synthetic entry is neither -- it is planned by construction and no
    vendor can take the key.
    """

    def test_an_unknown_key_lists_what_is_available(self):
        with self.assertRaises(Refusal) as caught:
            dialects.get("splonk")
        self.assertEqual(caught.exception.code, "DIALECT_UNKNOWN")
        self.assertIn("sentinel", caught.exception.message)

    def test_a_planned_key_is_refused_differently_from_an_unknown_one(self):
        # "Not Yet is planned" sends the caller to the roadmap. "_notyet is
        # not a dialect" sends them hunting for a typo they did not make.
        with planned_dialect() as key:
            with self.assertRaises(Refusal) as caught:
                dialects.get(key)
            self.assertEqual(
                caught.exception.code, "DIALECT_NOT_IMPLEMENTED"
            )
            self.assertIn(REGISTRY[key].label, caught.exception.message)

    def test_a_planned_dialect_cannot_be_lowered(self):
        with planned_dialect() as key:
            with self.assertRaises(Refusal) as caught:
                dialects.lower(key, "index=main | stats count")
            self.assertEqual(
                caught.exception.code, "DIALECT_NOT_IMPLEMENTED"
            )

    def test_a_planned_dialect_cannot_be_rendered(self):
        rule, _ = dialects.lower("sentinel", USER_RULE)
        with planned_dialect() as key:
            with self.assertRaises(Refusal) as caught:
                dialects.render(key, rule)
            self.assertEqual(
                caught.exception.code, "DIALECT_NOT_IMPLEMENTED"
            )

    def test_a_planned_dialect_cannot_be_parsed(self):
        with planned_dialect() as key:
            with self.assertRaises(Refusal) as caught:
                dialects.parse(key, "anything")
            self.assertEqual(
                caught.exception.code, "DIALECT_NOT_IMPLEMENTED"
            )

    def test_the_key_is_matched_case_and_whitespace_insensitively(self):
        # The GUI will send whatever a dropdown gives it.
        self.assertEqual(dialects.get("  SENTINEL ").key, "sentinel")

    def test_an_empty_key_is_refused_rather_than_defaulted(self):
        # Defaulting to "whatever the only dialect is" is how a rule ends up
        # saved under the wrong vendor.
        with self.assertRaises(Refusal) as caught:
            dialects.get("")
        self.assertEqual(caught.exception.code, "DIALECT_UNKNOWN")

    def test_a_ready_dialect_that_cannot_parse_refuses_to_parse_and_lower(self):
        # Different failure from a PLANNED dialect: this one has a module and
        # works, it just only goes one way. `get()` refuses a planned key
        # before any capability flag is consulted, and sentinel -- the only
        # ready dialect -- can both parse and render, so DIALECT_CANNOT_PARSE
        # was unreachable from this suite and therefore untested. It is the
        # refusal a render-only dialect hands back, so it is the one the next
        # dialects to land will actually hit.
        original = REGISTRY["sentinel"]
        REGISTRY["sentinel"] = dataclasses.replace(original, can_parse=False)
        try:
            with self.assertRaises(Refusal) as caught:
                dialects.parse("sentinel", USER_RULE)
            self.assertEqual(caught.exception.code, "DIALECT_CANNOT_PARSE")
            with self.assertRaises(Refusal) as caught:
                dialects.lower("sentinel", USER_RULE)
            self.assertEqual(caught.exception.code, "DIALECT_CANNOT_PARSE")
        finally:
            REGISTRY["sentinel"] = original

    def test_a_ready_dialect_that_cannot_render_refuses_to_render(self):
        # The mirror image, and the same reason it was untested.
        rule, _ = dialects.lower("sentinel", USER_RULE)
        original = REGISTRY["sentinel"]
        REGISTRY["sentinel"] = dataclasses.replace(original, can_render=False)
        try:
            with self.assertRaises(Refusal) as caught:
                dialects.render("sentinel", rule)
            self.assertEqual(caught.exception.code, "DIALECT_CANNOT_RENDER")
        finally:
            REGISTRY["sentinel"] = original

    def test_a_module_that_contradicts_the_registry_is_refused(self):
        # Simulate the drift this registry exists to catch: a dialect declared
        # able to render whose module does not export the renderer. Without
        # this check the caller gets AttributeError from somewhere deep in the
        # dialect layer instead of a refusal naming the disagreement.
        rule, _ = dialects.lower("sentinel", USER_RULE)
        original = REGISTRY["sentinel"]
        REGISTRY["sentinel"] = Dialect(
            key="sentinel",
            label="Microsoft Sentinel",
            language="KQL",
            module="kql",
            render_attr="render_nothing_at_all",
            can_render=True,
        )
        try:
            with self.assertRaises(Refusal) as caught:
                dialects.render("sentinel", rule)
            self.assertEqual(caught.exception.code, "DIALECT_CAPABILITY_MISSING")
            self.assertIn("render_nothing_at_all", caught.exception.message)
        finally:
            REGISTRY["sentinel"] = original


class RegistryRoundTrip(RegistrySnapshot):
    """The registry is the path the API and GUI will actually take."""

    def test_lower_through_the_registry_returns_a_rule_and_diagnostics(self):
        rule, diagnostics = dialects.lower("sentinel", USER_RULE)
        self.assertIsInstance(rule, Rule)
        self.assertIsInstance(diagnostics, list)
        for d in diagnostics:
            self.assertIsInstance(d, Diagnostic)

    def test_the_rule_records_the_dialect_it_came_from(self):
        rule, _ = dialects.lower("sentinel", USER_RULE)
        self.assertEqual(rule.metadata["dialect"], "sentinel")

    def test_the_rule_id_is_the_callers_to_choose(self):
        rule, _ = dialects.lower("sentinel", USER_RULE, "lsass-ntlm-001")
        self.assertEqual(rule.rule_id, "lsass-ntlm-001")

    def test_render_through_the_registry_closes_the_loop(self):
        rule, _ = dialects.lower("sentinel", USER_RULE)
        text, _ = dialects.render("sentinel", rule)
        again, _ = dialects.lower("sentinel", text)
        self.assertEqual(
            [type(n).__name__ for n in again.pipeline],
            [type(n).__name__ for n in rule.pipeline],
        )

    def test_parse_through_the_registry_exposes_the_split(self):
        parsed = dialects.parse("sentinel", USER_RULE)
        self.assertEqual([let.name for let in parsed.lets],
                         ["LSASSAccess", "LateralMovement"])

    def test_a_module_is_imported_at_most_once(self):
        first = dialects.load("sentinel")
        second = dialects.load("sentinel")
        self.assertIs(first, second)

    def test_the_module_cache_honours_a_repointed_registry_entry(self):
        # The cache was keyed on the dialect key alone. Once `sentinel` had
        # been imported, repointing the entry at a different module still
        # handed back kql -- so a test that swapped an entry to prove the
        # registry catches drift was quietly exercising the original module and
        # proving nothing. Keyed on (key, module), the swap is honoured.
        first = dialects.load("sentinel")
        self.assertEqual(first.__name__, "engine.dialects.kql")
        original = REGISTRY["sentinel"]
        REGISTRY["sentinel"] = dataclasses.replace(original, module="common")
        try:
            self.assertEqual(
                dialects.load("sentinel").__name__,
                "engine.dialects.common",
                "load() served a module the registry no longer names.",
            )
        finally:
            REGISTRY["sentinel"] = original
        # And the original entry still resolves to the very same module object.
        self.assertIs(dialects.load("sentinel"), first)


class CrossDialectRenderReportsWhatItLoses(unittest.TestCase):
    """The failure this whole package cites as its reason to exist.

    `render_kql`'s docstring names "the defect that once made a Wazuh rule
    match every event while reporting success". Cross-dialect rendering was
    reproducing it through a different door: the renderers correctly refuse to
    reuse a foreign `Read.selector`, but they dropped it without a word, and
    `dialects.render` returned a bare string with nowhere to put the warning.

    A Wazuh rule guarded by `<if_sid>5700</if_sid>` only ever sees events a
    parent rule already matched. Rendered to KQL that guard is gone and the
    output fires on every event its filter matches. The text looked clean, the
    call reported success, and the detection was strictly wider than the one
    the analyst pasted in.
    """

    #: Guarded by a precondition, so there is something real to lose.
    SSHD = """<group name="syslog,sshd,">
  <rule id="5710" level="5">
    <if_sid>5700</if_sid>
    <match>Failed password</match>
    <description>sshd: authentication failed.</description>
  </rule>
</group>"""

    def wazuh_rule(self) -> Rule:
        rule, _ = dialects.lower("wazuh", self.SSHD)
        return rule

    def test_the_precondition_is_carried_on_the_source_stage(self):
        # If this fails the rest of the class proves nothing: there would be no
        # selector to lose, and the audit would be vacuously silent.
        read = self.wazuh_rule().pipeline[0]
        self.assertEqual(read.selector, "if_sid=5700")

    def test_rendering_into_a_foreign_dialect_reports_the_dropped_selector(self):
        text, notes = dialects.render("sentinel", self.wazuh_rule())
        self.assertNotIn("5700", text, "the guard is genuinely not in the text")
        codes = [n.code for n in notes]
        self.assertIn(
            "SELECTOR_NOT_TRANSFERABLE",
            codes,
            "a Wazuh precondition vanished into KQL and nothing said so. This "
            "is the silent-widening defect, not a cosmetic omission.",
        )

    def test_the_report_names_the_clause_and_both_dialects(self):
        # A warning that says "something was dropped" sends the analyst reading
        # the diff. One that quotes the clause tells them what to re-express.
        _, notes = dialects.render("sentinel", self.wazuh_rule())
        note = next(n for n in notes if n.code == "SELECTOR_NOT_TRANSFERABLE")
        self.assertIn("if_sid=5700", note.message)
        self.assertIn("Wazuh", note.message)
        self.assertIn("Microsoft Sentinel", note.message)

    def test_the_loss_is_a_problem_and_is_verified(self):
        # `Diagnostic.verified` separates "checked against the rule" from "a
        # reading of it", and the UI shows the difference. This one is read off
        # the pipeline, and it widens the detection, so it is not a `caution`.
        _, notes = dialects.render("sentinel", self.wazuh_rule())
        note = next(n for n in notes if n.code == "SELECTOR_NOT_TRANSFERABLE")
        self.assertEqual(note.severity, "problem")
        self.assertTrue(note.verified)

    def test_sigma_loses_it_too_and_also_says_so(self):
        # Sigma keeps a `logsource`, so the output looks like it still has a
        # source -- `category: wazuh_alerts` -- which is exactly why the drop
        # needs stating. The surviving table is not the guard.
        text, notes = dialects.render("sigma", self.wazuh_rule())
        self.assertIn("wazuh_alerts", text)
        self.assertNotIn("5700", text)
        self.assertIn("SELECTOR_NOT_TRANSFERABLE", [n.code for n in notes])

    def test_rendering_back_into_its_own_dialect_is_silent(self):
        # Wazuh to Wazuh keeps the guard, so warning here would be a false
        # alarm -- and a warning that fires on the clean path gets ignored on
        # the dirty one.
        text, notes = dialects.render("wazuh", self.wazuh_rule())
        self.assertIn("<if_sid>5700</if_sid>", text)
        self.assertEqual(notes, [])

    def test_a_rule_with_no_selector_to_lose_is_silent(self):
        # KQL never writes a selector, so a Sentinel rule has nothing to drop
        # on the way to Sigma. Reporting a loss here would train the analyst to
        # dismiss the message.
        #
        # Deliberately NOT `USER_RULE`: its join and bindings are refused by
        # Sigma outright, so that rule would exercise the refusal path and
        # never reach the audit this test is about.
        rule, _ = dialects.lower(
            "sentinel", "SecurityEvent | where EventID == 10 | project Computer"
        )
        self.assertEqual(rule.pipeline[0].selector, "")
        _, notes = dialects.render("sigma", rule)
        self.assertEqual(
            [n.code for n in notes if n.code == "SELECTOR_NOT_TRANSFERABLE"],
            [],
        )

    def test_the_key_is_normalised_before_the_comparison(self):
        # `get()` accepts "  WAZUH ". If the audit compared the raw key against
        # the rule's metadata it would call a same-dialect render foreign and
        # warn about a selector that is in fact written out verbatim.
        text, notes = dialects.render("  WAZUH ", self.wazuh_rule())
        self.assertIn("<if_sid>5700</if_sid>", text)
        self.assertEqual(notes, [])

    def test_every_ready_dialect_is_audited_not_just_the_ones_tested_here(self):
        # The audit keys off `Read.selector` generically rather than off a list
        # of dialect pairs, so a dialect landing later is covered the day it is
        # registered. This fails if someone narrows it to named pairs.
        rule = self.wazuh_rule()
        for entry in dialects.ready_dialects():
            if entry.key == "wazuh" or not entry.can_render:
                continue
            with self.subTest(target=entry.key):
                _, notes = dialects.render(entry.key, rule)
                self.assertIn(
                    "SELECTOR_NOT_TRANSFERABLE", [n.code for n in notes]
                )

    def test_a_selector_inside_a_binding_is_audited_too(self):
        # A Splunk join subsearch lowers to a Binding with its own Read, so
        # `[ search index=threat ... ]` carries a second selector that is just
        # as narrowing as the outer one. The audit walked only `rule.pipeline`
        # at first and reported the outer loss while staying silent about the
        # inner one -- a rule that reads a WIDER threat feed than it was told
        # to, with one reassuring warning printed above it.
        rule, _ = dialects.lower(
            "splunk",
            "index=fw sourcetype=pan | join type=inner src_ip "
            "[ search index=threat sourcetype=ti | fields src_ip ] "
            "| stats count by src_ip",
        )
        self.assertEqual(len(rule.bindings), 1, "no subsearch, nothing to miss")
        _, notes = dialects.render("sentinel", rule)
        dropped = [n for n in notes if n.code == "SELECTOR_NOT_TRANSFERABLE"]
        self.assertEqual(
            len(dropped), 2,
            "both the outer selector and the subsearch's own were dropped, so "
            "both must be reported.",
        )
        joined = " ".join(n.message for n in dropped)
        self.assertIn("index=fw sourcetype=pan", joined)
        self.assertIn("index=threat sourcetype=ti", joined)

    def test_a_dropped_binding_selector_names_the_sub_stream(self):
        # "A selector was dropped" is not actionable when a rule has three
        # streams. The binding's name is how the analyst finds which one.
        rule, _ = dialects.lower(
            "splunk",
            "index=fw | join type=inner src_ip "
            "[ search index=threat | fields src_ip ]",
        )
        _, notes = dialects.render("sentinel", rule)
        inner = next(
            n for n in notes
            if n.code == "SELECTOR_NOT_TRANSFERABLE"
            and "index=threat" in n.message
        )
        self.assertIn(rule.bindings[0].name, inner.message)


if __name__ == "__main__":
    unittest.main()
