#!/usr/bin/env python3
"""One-site oracle mutations: each named verifier bug must flip the required outcome on its named
witness case while the positive control (and a negative control) stay exactly as expected."""

import json
from pathlib import Path
import sys

import schema_check as baseline

HERE = Path(__file__).resolve().parent
CONTROLS = ["A1_CONTROL_CURRENT_AUTHORIZED", "N8_DECISION_REF_TAMPERED"]
ANY_STATE = "any(set(names) == set(state) for state in states)"
MUTANTS = [
    ("M1_DECLARED_SET_TRUSTED_DIRECTLY", "N1_SELF_CONSISTENT_REDUCED_PREIMAGE", ANY_STATE, "True"),
    ("M2_RECOMPUTE_FAILURE_BYPASSES_AUTHORIZATION", "N7_RECOMPUTE_FAILURE_MUST_NOT_BYPASS_AUTHORIZATION",
     'if signature == "satisfied" and schema == "satisfied" and recompute == "satisfied":  # M2/M8',
     'if recompute == "cannot_establish" and signature == "satisfied" or (signature == "satisfied" and '
     'schema == "satisfied" and recompute == "satisfied"):  # M2/M8'),
    ("M3_DUPLICATE_NAMES_SILENTLY_DEDUPED", "N4_DUPLICATE_NAME_MALFORMED",
     "if len(set(declared)) != len(declared):  # M3", "if False:  # M3"),
    ("M4_NON_STRING_ENTRIES_COERCED_AWAY", "N5_NON_STRING_ENTRY_MALFORMED",
     "if not (isinstance(declared, list) and all(type(f) is str for f in declared)):  # M4",
     "if isinstance(declared, list):\n        declared = [f for f in declared if type(f) is str]\n"
     "    if not isinstance(declared, list):  # M4"),
    ("M5_UNKNOWN_POLICY_VERSION_ACCEPTED", "N3_UNREGISTERED_POLICY_VERSION",
     "if states is None:  # M5",
     'if states is None:\n        return "satisfied", "DECLARED_SET_REGISTERED"\n    if False:  # M5'),
    ("M6_PROPER_SUBSET_ACCEPTED", "N1_SELF_CONSISTENT_REDUCED_PREIMAGE",
     ANY_STATE, "any(set(names) <= set(state) for state in states)"),
    ("M7_SUPERSET_ACCEPTED", "N2_SUPERSET_WITH_UNREGISTERED_FIELD",
     ANY_STATE, "any(set(names) >= set(state) for state in states)"),
    ("M8_SIGNATURE_NOT_CHECKED", "N9_SIGNATURE_INVALID_ISOLATED",
     'if signature == "satisfied" and schema == "satisfied" and recompute == "satisfied":  # M2/M8',
     'if schema == "satisfied" and recompute == "satisfied":  # M2/M8'),
    ("M9_LIST_ORDER_TREATED_AS_IDENTITY", "A2_REORDERED_DECLARED_LIST_SAME_SET",
     ANY_STATE, "any(list(names) == list(state) for state in states)"),
    ("M10_ANY_VERSIONS_REGISTRY_ACCEPTED", "N10_CURRENT_SET_UNDER_OLD_VERSION",
     ANY_STATE, 'any(set(names) == set(state) for group in registry["states"].values() for state in group)'),
    ("M11_ONE_VERSION_ONE_SCHEMA_ASSUMED", "A4_V18_REGISTERED_STATE_2",
     ANY_STATE, "set(names) == set(states[0])"),
]


def main():
    document = baseline.load_document(HERE / "vectors.json")
    registry, pubkey = document["registry"], document["trusted_pubkey"]
    cases = document["cases"]
    by_id = {c["case_id"]: c for c in cases}
    if any(baseline.evaluate(c, registry, pubkey) != c["expected"] for c in cases):
        print(json.dumps({"status": "BASELINE_FAILED"}))
        return 1
    if any(cid not in by_id for cid in CONTROLS) or by_id[CONTROLS[0]]["expected"]["required_verification_outcome"] != "accept" \
            or by_id[CONTROLS[1]]["expected"]["required_verification_outcome"] != "reject":
        print(json.dumps({"status": "INVALID_CONTROLS"}))
        return 1
    source = (HERE / "schema_check.py").read_text(encoding="utf-8")
    records = []
    for name, killer, before, after in MUTANTS:
        entry = {"mutant": name, "required_killer": killer, "axis": "required_verification_outcome"}
        if by_id.get(killer) is None:
            entry["status"] = "UNKNOWN_KILLER"
        elif source.count(before) != 1:
            entry["status"] = "NOT_APPLIED"
        else:
            try:
                ns = {"__name__": "schema_mutant"}
                exec(compile(source.replace(before, after, 1), name, "exec"), ns)
                controls_ok = all(ns["evaluate"](by_id[cid], registry, pubkey) == by_id[cid]["expected"]
                                  for cid in CONTROLS)
                expected = by_id[killer]["expected"]
                actual = ns["evaluate"](by_id[killer], registry, pubkey)
                killed = actual["required_verification_outcome"] != expected["required_verification_outcome"]
                entry.update(controls_preserved=controls_ok,
                             expected_required=expected["required_verification_outcome"],
                             mutant_required=actual["required_verification_outcome"],
                             status="CONTROL_BROKEN" if not controls_ok else "KILLED" if killed else "SURVIVED")
            except Exception as error:
                entry.update(status="CRASH", error=type(error).__name__)
        records.append(entry)
    counts = {s: sum(r["status"] == s for r in records)
              for s in ("KILLED", "SURVIVED", "CRASH", "NOT_APPLIED", "CONTROL_BROKEN", "UNKNOWN_KILLER")}
    print(json.dumps({"mutations": records, "counts": counts, "controls": CONTROLS}, sort_keys=True, indent=2))
    return 0 if counts["KILLED"] == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
