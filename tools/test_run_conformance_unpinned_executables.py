"""Regression: files a suite EXECUTES must be covered by a declared pin, or be reported.

pipavlo82 on trustless-ai/recompute-kit#53: "DECLARED PIN != COMPLETE EXECUTABLE PIN CLOSURE" -- every declared pin
can be valid while an executed-but-undeclared checker changes silently. unpinned_executables() lists them.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_conformance as runner  # noqa: E402


def _suite(tmp, manifest, files):
    d = pathlib.Path(tmp) / "suite-x"
    d.mkdir()
    (d / "suite.json").write_text(json.dumps(manifest))
    for n, c in files.items():
        (d / n).write_text(c)
    return d


class UnpinnedExecutablesTests(unittest.TestCase):
    def test_executed_gate_without_a_pin_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _suite(tmp, {"adapter": {"kind": "stdio", "cmd": "python gate.py --grade"},
                             "vectors": {"path": "v.json", "sha256": "x"}}, {"gate.py": "", "v.json": "{}"})
            self.assertEqual(runner.unpinned_executables(d), ["gate.py"])

    def test_pinned_checker_is_not_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _suite(tmp, {"adapter": {"kind": "stdio", "cmd": "python gate.py"},
                             "checker": {"path": "gate.py", "sha256": "abc"}}, {"gate.py": ""})
            self.assertEqual(runner.unpinned_executables(d), [])

    def test_pin_without_sha_does_not_count_as_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _suite(tmp, {"adapter": {"kind": "stdio", "cmd": "python gate.py"},
                             "checker": {"path": "gate.py"}}, {"gate.py": ""})
            self.assertEqual(runner.unpinned_executables(d), ["gate.py"])

    def test_multi_check_suite_and_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _suite(tmp, {"checks": [{"name": "a", "adapter": {"cmd": "node ref.mjs && python loop_gate.py"}},
                                        {"name": "b", "adapter": {"cmd": "bun vectors.js"}}],
                             "dependencies": [{"path": "ref.mjs", "sha256": "1"}]},
                       {"ref.mjs": "", "loop_gate.py": "", "vectors.js": ""})
            self.assertEqual(runner.unpinned_executables(d), ["loop_gate.py", "vectors.js"])

    def test_non_file_tokens_and_interpreters_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = _suite(tmp, {"adapter": {"cmd": "python3 -m json.tool missing.py"}}, {})
            self.assertEqual(runner.unpinned_executables(d), [])

    def test_scope_is_direct_closure_only_imports_and_dash_m_are_not_reported(self):
        # Documented scope (#54): an imported helper and a `python -m` target are outside this check -- the empty
        # result must not be read as transitive closure.
        with tempfile.TemporaryDirectory() as tmp:
            d = _suite(tmp, {"adapter": {"cmd": "python gate.py && python -m helpers.grade"},
                             "checker": {"path": "gate.py", "sha256": "abc"}},
                       {"gate.py": "import helper\n", "helper.py": "", "helpers.py": ""})
            self.assertEqual(runner.unpinned_executables(d), [])
            self.assertIn("does NOT establish transitive closure", runner.unpinned_executables.__doc__)


if __name__ == "__main__":
    unittest.main()
