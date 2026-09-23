"""Regression: a declared checker / mutation_checker / dependencies sha256 pin is enforced like
vectors.sha256 and spec.sha256. Before this, editing mutation_check.py without repinning still passed.

  - control: every declared pin matches -> the suite runs and passes;
  - each of checker, mutation_checker and a dependency edited after pinning -> DRIFT;
  - a pinned file that is missing -> NOT COVERED, never a silent skip;
  - a manifest that pins none of them is unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_conformance as runner  # noqa: E402


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _suite(tmp: str, pin_checker=True, pin_mutation=True, pin_dep=True) -> pathlib.Path:
    d = pathlib.Path(tmp) / "suite-x"
    d.mkdir()
    files = {"check.py": b"import sys\nsys.stdin.read()\n", "mutation.py": b"print('m')\n", "dep.py": b"print('d')\n", "vectors.json": b"[]"}
    for n, b in files.items():
        (d / n).write_bytes(b)
    m = {"vectors": {"path": "vectors.json", "sha256": _h(files["vectors.json"])}, "adapter": {"kind": "stdio", "cmd": "python3 check.py"}}
    if pin_checker:
        m["checker"] = {"path": "check.py", "sha256": _h(files["check.py"])}
    if pin_mutation:
        m["mutation_checker"] = {"path": "mutation.py", "sha256": _h(files["mutation.py"])}
    if pin_dep:
        m["dependencies"] = [{"path": "dep.py", "sha256": _h(files["dep.py"])}]
    (d / "suite.json").write_text(json.dumps(m))
    return d


class CheckerPinTests(unittest.TestCase):
    def _run(self, d):
        return runner.run_suite(d)[0]

    def test_control_matching_pins_pass(self):
        with tempfile.TemporaryDirectory() as t:
            r = self._run(_suite(t))
            self.assertTrue(r.ok, (r.kind, r.detail))

    def test_edited_files_after_pinning_are_drift(self):
        for fname, key in (("check.py", "checker"), ("mutation.py", "mutation_checker"), ("dep.py", "dependencies")):
            with self.subTest(fname):
                with tempfile.TemporaryDirectory() as t:
                    d = _suite(t)
                    (d / fname).write_bytes((d / fname).read_bytes() + b"# edited\n")
                    r = self._run(d)
                    self.assertFalse(r.ok)
                    self.assertEqual(r.kind, "DRIFT")
                    self.assertIn(key, r.detail)

    def test_missing_pinned_file_is_not_covered(self):
        with tempfile.TemporaryDirectory() as t:
            d = _suite(t)
            (d / "mutation.py").unlink()
            r = self._run(d)
            self.assertFalse(r.ok)
            self.assertEqual(r.kind, "NOT COVERED")

    def test_unpinned_manifest_unchanged(self):
        with tempfile.TemporaryDirectory() as t:
            d = _suite(t, pin_checker=False, pin_mutation=False, pin_dep=False)
            (d / "check.py").write_bytes(b"import sys\nsys.stdin.read()\n# edited\n")
            self.assertTrue(self._run(d).ok)


if __name__ == "__main__":
    unittest.main()
