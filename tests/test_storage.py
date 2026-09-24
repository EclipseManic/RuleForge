import tempfile
import unittest
from pathlib import Path

from storage import RuleStore


class RuleStoreTests(unittest.TestCase):
    def test_history_persists_and_lists(self):
        with tempfile.TemporaryDirectory() as directory:
            store = RuleStore(Path(directory) / "rules.db")
            record = store.record_history(
                "generated", "Rule A", "wazuh, sentinel", "Generated 2 templates",
                {"title": "Rule A"}, {"rules": []},
            )
            history = store.list_history()
            self.assertEqual(history[0]["id"], record["id"])
            self.assertEqual(history[0]["payload"]["title"], "Rule A")
            store.clear_history()
            self.assertEqual(store.list_history(), [])
