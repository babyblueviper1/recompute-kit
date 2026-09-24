"""Regression: requires_live exclusions age visibly (pipavlo82 on trustless-ai/recompute-kit#52).
Past review_after an exclusion no longer excuses its suite; undated exclusions are reported."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_conformance as runner  # noqa: E402


class LiveExclusionLifecycleTests(unittest.TestCase):
    def test_future_review_after_still_excuses(self):
        self.assertFalse(runner._live_exclusion_overdue({"review_after": "2026-10-24"}, today="2026-09-24"))

    def test_past_review_after_no_longer_excuses(self):
        self.assertTrue(runner._live_exclusion_overdue({"review_after": "2026-10-24"}, today="2026-10-25"))

    def test_review_after_day_itself_still_excuses(self):
        self.assertFalse(runner._live_exclusion_overdue({"review_after": "2026-10-24"}, today="2026-10-24"))

    def test_undated_entry_is_not_overdue_but_is_reported_undated(self):
        self.assertFalse(runner._live_exclusion_overdue({}, today="2030-01-01"))

    def test_current_manifest_entries_are_dated(self):
        undated, overdue = runner.live_exclusion_lifecycle(today="2026-09-24")
        self.assertEqual(undated, [])
        self.assertEqual(overdue, [])


if __name__ == "__main__":
    unittest.main()
