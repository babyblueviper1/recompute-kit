#!/usr/bin/env python3
"""Check supplied admission traces; this is not a writer or a storage CAS."""

import hashlib
import json
from pathlib import Path
import sys

PROFILE = "event_time_concurrency_boundary.v0"
MODES = {"EVENT_REEVALUATED", "PERIODIC_PASS_ONLY"}
DISCIPLINES = {"UNSPECIFIED", "SINGLE_WRITER", "SERIALIZED"}


class InvalidTrace(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidTrace("malformed or contradictory trace coordinates")


def natural(value):
    return type(value) is int and value >= 0


def identity(ref):
    # A local unambiguous encoding, not a backfill of captured-admission.v0 bytes.
    preimage = json.dumps([PROFILE, ref], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(preimage.encode("ascii")).hexdigest()


def evaluate(case):
    """No expected values or case IDs participate in evaluation."""
    try:
        return _evaluate(case["inputs"])
    except (InvalidTrace, KeyError, TypeError, IndexError):
        return {
            "event_time_status": "cannot_establish",
            "concurrency_status": "cannot_establish",
            "idempotency_status": "cannot_establish",
            "admission_result": "cannot_establish",
            "reason_codes": ["INVALID_TRACE"],
            "transition_count": None,
            "final_state_version": None,
            "observed_results": [],
        }


def _evaluate(data):
    initial = data["initial"]
    version = initial["state_version"]
    policy = initial["policy_version"]
    ceiling = initial["ceiling"]
    require(all(natural(x) for x in (version, policy, ceiling)))
    discipline = data["discipline"]
    require(discipline in DISCIPLINES and type(data["idempotency"]) is bool)
    keyed = data["idempotency"]
    writers = data["writers"]
    require(isinstance(writers, dict) and bool(writers))
    refs = {}
    for writer, request in writers.items():
        require(isinstance(writer, str) and bool(writer))
        ref, amount = request["canonical_capture_ref"], request["amount"]
        require(isinstance(ref, str) and bool(ref) and natural(amount))
        require(ref not in refs or refs[ref] == amount)
        refs[ref] = amount
    schedule = data["schedule"]
    require(isinstance(schedule, list) and bool(schedule))
    active, finished, audits, receipts = {}, set(), {}, {}
    event_bad, concurrency_bad, idem_bad = set(), set(), set()
    event_unknown, concurrency_unknown = set(), set()
    results = []
    transitions = 0
    used_cas = False
    next_index = 0
    for step in schedule:
        op = step["op"]
        if op == "POLICY":
            require(natural(step["policy_version"]) and step["policy_version"] == policy + 1)
            require(natural(step["ceiling"]))
            policy, ceiling = step["policy_version"], step["ceiling"]
            continue
        writer = step["writer"]
        require(writer in writers)
        request = writers[writer]
        aid = identity(request["canonical_capture_ref"])
        if op == "AUDIT":
            require(writer not in active and writer not in finished)
            audits[writer] = (policy, request["amount"] <= ceiling)
        elif op == "READ":
            require(writer not in active and writer not in finished)
            require(natural(step["expected_version"]) and step["expected_version"] == version)
            overlapped = bool(active)
            if active:
                for other in active.values():
                    other["overlapped"] = True
                if discipline != "UNSPECIFIED":  # M6: enforce declared exclusion
                    concurrency_bad.add("SERIALIZATION_OVERLAP")
            active[writer] = {"expected": version, "check": None, "overlapped": overlapped}
        elif op == "CHECK":
            require(writer in active and active[writer]["check"] is None)
            mode = step["mode"]
            require(mode in MODES)
            if mode == "EVENT_REEVALUATED":
                coordinate, passed = policy, request["amount"] <= ceiling
            else:
                require(writer in audits)
                coordinate, passed = audits[writer]
            active[writer]["check"] = (mode, coordinate, passed)
        elif op in {"WRITE", "CAS"}:
            require(writer in active)
            attempt = active.pop(writer)
            finished.add(writer)
            outcome = step["outcome"]
            require(outcome in {"commit", "reject", "replay"})
            check = attempt["check"]
            expected = attempt["expected"]
            if op == "CAS":
                used_cas = True
            if outcome == "replay":
                require(keyed and aid in receipts and natural(step["index"]))
                if step["index"] != receipts[aid]:
                    idem_bad.add("REPLAY_RECEIPT_CHANGED")
                # Returning a receipt is not a new authorization or transition.
            elif outcome == "commit":
                require(natural(step["index"]) and step["index"] == next_index)
                next_index += 1
                if check is None:  # M2: a READ or old audit is not an event check
                    event_bad.add("EVENT_CHECK_MISSING")
                elif check[0] != "EVENT_REEVALUATED":  # M1: periodic PASS is insufficient
                    event_bad.add("PERIODIC_PASS_NOT_AUTHORITY")
                elif check[1] != policy:
                    event_bad.add("EVENT_POLICY_VERSION_STALE")
                elif not check[2]:
                    event_bad.add("PREDICATE_FALSE")
                if op == "CAS":
                    if expected != version:  # M3/M5: compare at the protected transition
                        concurrency_bad.add("CAS_VERSION_MISMATCH")
                elif discipline == "UNSPECIFIED":
                    if attempt["overlapped"]:  # M4/M7: this attempt's active interval
                        concurrency_bad.add("NONATOMIC_CONCURRENT_WRITE")
                    else:
                        concurrency_unknown.add("NO_ATOMIC_OR_SERIALIZATION_EVIDENCE")
                elif expected != version:
                    concurrency_bad.add("SERIALIZED_STALE_WRITE")
                if keyed:
                    if aid in receipts:
                        idem_bad.add("SECOND_TRANSITION_SAME_IDENTITY")
                    else:
                        receipts[aid] = step["index"]
                # Follow the supplied observation even when unsafe; do not repair it.
                version += 1
                transitions += 1
            else:
                require("index" not in step)
                if check is None or check[0] != "EVENT_REEVALUATED":
                    event_unknown.add("REJECTION_WITHOUT_EVENT_CHECK")
            results.append({"writer": writer, "outcome": outcome, "index": step.get("index")})
        else:
            raise InvalidTrace("unknown operation")
    if active or finished != set(writers):
        event_unknown.add("INCOMPLETE_SCHEDULE")
        concurrency_unknown.add("INCOMPLETE_SCHEDULE")
    event = "violated" if event_bad else "cannot_establish" if event_unknown else "satisfied"
    concurrency = ("violated" if concurrency_bad else
                   "cannot_establish" if concurrency_unknown else "satisfied")
    idem = ("not_applicable" if not keyed else "violated" if idem_bad else
            "cannot_establish" if active or finished != set(writers) else "satisfied")
    reasons = event_bad | concurrency_bad | idem_bad | event_unknown | concurrency_unknown
    if event == "satisfied":
        reasons.add("EVENT_TIME_ESTABLISHED")
    if concurrency == "satisfied":
        reasons.add("SAFE_UNDER_MODELED_SERIALIZATION_ASSUMPTION" if discipline != "UNSPECIFIED"
                    else "CAS_SCHEDULE_CHECKED" if used_cas else "NO_PROTECTED_TRANSITION")
    if idem == "satisfied":
        reasons.add("IDENTITY_RECEIPT_MAPPING_PRESERVED")
    statuses = (event, concurrency, idem)
    admission = ("reject" if "violated" in statuses else
                 "cannot_establish" if "cannot_establish" in statuses else
                 "admit" if transitions or any(r["outcome"] == "replay" for r in results) else "reject")
    return {
        "event_time_status": event,
        "concurrency_status": concurrency,
        "idempotency_status": idem,
        "admission_result": admission,
        "reason_codes": sorted(reasons),
        "transition_count": transitions,
        "final_state_version": version,
        "observed_results": results,
    }


def load_cases(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    require(document["profile"] == PROFILE and bool(document["cases"]))
    cases = document["cases"]
    require(len({c["case_id"] for c in cases}) == len(cases))
    return cases


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("vectors.json")
    cases = load_cases(path)
    results = [{"case_id": c["case_id"], "result": evaluate(c),
                "reproduced": evaluate(c) == c["expected"]} for c in cases]
    counts = {axis: {status: sum(r["result"][axis] == status for r in results)
                     for status in ("satisfied", "violated", "cannot_establish")}
              for axis in ("event_time_status", "concurrency_status")}
    print(json.dumps({"results": results, "counts": counts,
                      "reproduced": sum(r["reproduced"] for r in results), "total": len(cases)},
                     sort_keys=True, indent=2))
    return 0 if all(r["reproduced"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
