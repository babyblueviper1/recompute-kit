"""Required case corpora are evidence: zero cases cannot certify conformance.

Run real semantic owners and the canonical execution path in a disposable copy.
Intentional corpus/source probes are repinned so DRIFT cannot masquerade as the
empty-corpus refusal. Reporter adapters and their grading contract are unchanged.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_conformance as runner

ROOT = Path(__file__).resolve().parent.parent
# Every affected manifest check, including shared executables and JS references.
CHECKS = {
    "captured-admission-v0": 63,
    "captured-admission-v0-review-profile": 10,
    "captured-admission-v0-review-profile-deadline": 8,
    "companion-envelope-v0/envelope": 5,
    "companion-envelope-v0/envelope-reference-ts": 5,
    "pq-key-binding-v0/cutoff": 8,
    "pq-key-binding-v0/rotation": 7,
    "pq-key-binding-v0/revocation": 6,
    "pq-key-binding-v1/cutoff": 32,
    "pq-key-binding-v1/manifest": 7,
    "pq-key-binding-v1-profile": 15,
    "pq-recovery-classes-v0": 20,
    "profile-amendment-v0/amendment": 8,
    "profile-amendment-v0/amendment-reference-ts": 8,
    "profile-commitment-loop-v0/loop": 6,
    "profile-commitment-loop-v0/loop-reference-ts": 6,
    "scan-subject-binding-v0/conformance": 12,
    "serializer-bindings/shape": 15,
    "verdict-profile-binding-v0/binding": 6,
    "verdict-profile-binding-v0/binding-reference-ts": 6,
    "encode-json-utf8-lf-v0": 48,
}
ENCODE = "encode-json-utf8-lf-v0"


def pins(value):
    if isinstance(value, dict):
        if isinstance(value.get("path"), str) and "sha256" in value:
            yield value
        for child in value.values():
            yield from pins(child)
    elif isinstance(value, list):
        for child in value:
            yield from pins(child)


def remove_guard(source, javascript=False):
    if javascript:
        pattern = r'if \(Array\.isArray\(doc\.vectors\) && doc\.vectors\.length === 0\) \{\n[^}]*ZERO_CASES[^}]*\}\n'
        changed, count = re.subn(pattern, "", source)
        if count != 1:
            raise ValueError("expected exactly one ZERO_CASES guard")
        return changed
    lines = source.splitlines(keepends=True)
    guards = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.If)
              and any(isinstance(s, ast.Expr) and "ZERO_CASES" in ast.get_source_segment(source, s)
                      for s in n.body)]
    if len(guards) != 1:
        raise ValueError("expected exactly one ZERO_CASES guard")
    guard = guards[0]
    return "".join(lines[:guard.lineno - 1] + lines[guard.end_lineno:])


class NonemptySelfGradingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="self-grading-corpora-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.repo = Path(cls.tmp.name) / "repo"
        shutil.copytree(ROOT, cls.repo, ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__", "*.pyc"))
        cls.env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
        cls.flags = ["-B"] + (["-O"] if sys.flags.optimize else [])

    def declaration(self, check):
        suite, _, name = check.partition("/")
        directory = self.repo / "conformance" / suite
        manifest = json.loads((directory / "suite.json").read_text(encoding="utf-8"))
        if name:
            selected = next(c for c in manifest.pop("checks") if c["name"] == name)
            manifest.update(selected)
        return directory, manifest

    def paths(self, check):
        directory, manifest = self.declaration(check)
        return directory / manifest["vectors"]["path"], (directory / shlex.split(manifest["adapter"]["cmd"])[1]).resolve()

    def command(self, check):
        directory, manifest = self.declaration(check)
        args = shlex.split(manifest["adapter"]["cmd"])
        if args[0] in {"python", "python3"}:
            args = [sys.executable, *self.flags, *args[1:]]
        return directory, args

    def native(self, check, controls=False):
        directory, args = self.command(check)
        if controls:
            args[-1] = "--negative-controls"
        vector, _ = self.paths(check)
        return subprocess.run(args, cwd=directory, env=self.env, input=vector.read_bytes() if vector.exists() else b"",
                              capture_output=True, timeout=120)

    def canonical(self, check):
        directory, manifest = self.declaration(check)
        _, args = self.command(check)
        manifest["adapter"]["cmd"] = subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)
        return runner._run_one(directory, manifest, check)

    def repin(self, target):
        for path in (self.repo / "conformance").glob("*/suite.json"):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            changed = False
            for pin in pins(manifest):
                if (path.parent / pin["path"]).resolve() == target.resolve():
                    pin["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
                    changed = True
            if changed:
                path.write_text(json.dumps(manifest), encoding="utf-8", newline="\n")

    @contextmanager
    def probe(self, check, mode, repin=True):
        vector, owner = self.paths(check)
        files = [vector, owner, *(self.repo / "conformance").glob("*/suite.json")]
        original = {p: p.read_bytes() for p in files}
        document = json.loads(original[vector])
        key = "cases" if "cases" in document else "vectors"
        try:
            if mode == "missing":
                vector.unlink()
            elif mode == "malformed":
                vector.write_bytes(b'{"cases":')
            else:
                corpus = document[key]
                if mode == "empty":
                    document[key] = {} if isinstance(corpus, dict) else []
                elif mode == "null":
                    document[key] = None
                elif mode == "refuted":
                    case = next(iter(corpus.values())) if isinstance(corpus, dict) else corpus[0]
                    if check == ENCODE:
                        case["expect"]["byte_length"] += 1
                    elif "expected_verdict" in case:
                        case["expected_verdict"] = "__WRONG_VERDICT__"
                    else:
                        field = "expect" if "expect" in case else "expected"
                        expected = case[field]
                        if isinstance(expected, dict):
                            expected[next(iter(expected))] = "__WRONG_RESULT__"
                        else:
                            case[field] = "__WRONG_RESULT__"
                vector.write_text(json.dumps(document, ensure_ascii=True), encoding="utf-8", newline="\n")
            if repin and vector.exists():
                self.repin(vector)
            yield vector, owner
        finally:
            for path, data in original.items():
                path.write_bytes(data)

    def assert_empty(self, check, controls=False):
        process = self.native(check, controls)
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertIn(b"ZERO_CASES", process.stderr)
        self.assertNotIn(b"PASS", process.stdout)
        self.assertNotIn(b"NEGATIVE CONTROL RED", process.stdout)
        result = self.canonical(check)
        self.assertEqual((result.ok, result.kind), (False, "UNVERIFIABLE"), result.detail)
        self.assertIn("ZERO_CASES", result.detail)
        self.assertEqual(runner.exit_code_for_failures([result]), 2)

    def test_nonempty_corpora_reproduce(self):
        for check, count in CHECKS.items():
            with self.subTest(check=check):
                process = self.native(check)
                self.assertEqual(process.returncode, 0, process.stderr)
                if check == "scan-subject-binding-v0/conformance":
                    result = json.loads(process.stdout)
                    self.assertEqual((result["total"], result["reproduced"]), (count, count))
                else:
                    self.assertIn(f"{count}/{count}".encode(), process.stdout)

    def test_repinned_empty_is_unverifiable(self):
        for check in CHECKS:
            with self.subTest(check=check), self.probe(check, "empty"):
                self.assert_empty(check)

    def test_stale_pin_is_drift_not_empty_refusal(self):
        for check in CHECKS:
            with self.subTest(check=check), self.probe(check, "empty", repin=False):
                result = self.canonical(check)
                self.assertEqual((result.ok, result.kind), (False, "DRIFT"), result.detail)
                self.assertNotIn("ZERO_CASES", result.detail)

    def test_malformed_and_missing_are_not_empty(self):
        for check in CHECKS:
            for mode in ("malformed", "null", "missing"):
                with self.subTest(check=check, mode=mode), self.probe(check, mode):
                    process = self.native(check)
                    self.assertNotEqual(process.returncode, 0)
                    self.assertFalse(any(line.startswith(b"UNVERIFIABLE") and b"ZERO_CASES" in line
                                         for line in (process.stdout + process.stderr).splitlines()))
                    result = self.canonical(check)
                    self.assertFalse(result.ok)
                    self.assertEqual(result.kind, "NOT COVERED" if mode == "missing" else "SUITE", result.detail)

    def test_real_semantic_mismatch_is_exit_one(self):
        for check in CHECKS:
            with self.subTest(check=check), self.probe(check, "refuted"):
                process = self.native(check)
                self.assertEqual(process.returncode, 1, process.stderr)
                self.assertNotIn(b"Traceback", process.stderr)
                self.assertNotIn(b"ZERO_CASES", process.stdout + process.stderr)
                result = self.canonical(check)
                self.assertEqual((result.ok, result.kind), (False, "SUITE"), result.detail)

    def test_each_guard_prevents_old_false_success(self):
        seen = set()
        for check in CHECKS:
            _, owner = self.paths(check)
            if owner in seen:
                continue
            seen.add(owner)
            with self.subTest(check=check), self.probe(check, "empty"):
                owner.write_text(remove_guard(owner.read_text(encoding="utf-8"), owner.suffix == ".mjs"),
                                 encoding="utf-8", newline="\n")
                self.repin(owner)
                process = self.native(check, controls=check == ENCODE)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertNotIn(b"ZERO_CASES", process.stdout + process.stderr)
                if check == ENCODE:
                    self.assertIn(b"PASS negative controls: 6/6", process.stdout)
                else:
                    self.assertTrue(self.canonical(check).ok)

    def test_encode_controls_require_cases_too(self):
        with self.probe(ENCODE, "empty"):
            self.assert_empty(ENCODE, controls=True)

    def test_existing_nonempty_requirements_remain_red(self):
        checks = ["predicate-conformance-v0", "provenance-anchor-v0/origination-gate",
                  "scan-subject-binding-v0/mutation-coverage"]
        for suite in ("authorized-preimage-schema-v0", "consumption-time-state-binding-v0",
                      "event-time-concurrency-boundary-v0", "permission-consumption-boundary-v0"):
            checks.extend([suite + "/conformance", suite + "/mutation-coverage"])
        for check in checks:
            with self.subTest(check=check), self.probe(check, "empty"):
                self.assertNotEqual(self.native(check).returncode, 0)
                self.assertFalse(self.canonical(check).ok)

    def test_no_bytecode_in_disposable_copy(self):
        self.assertEqual(list(self.repo.rglob("*.pyc")), [])


if __name__ == "__main__":
    unittest.main()
