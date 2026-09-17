#!/usr/bin/env python3
"""Finite supplied histories: event-time evaluation != consumption-time validity."""

import json
from pathlib import Path
import sys

PROFILE = "consumption_time_state_binding.v0"
MODES = {"UNBOUND", "VERSION_BOUND", "REEVALUATE"}


def require(condition):
    if not condition:
        raise ValueError("invalid history")


def natural(value):
    return type(value) is int and value >= 0


def state_valid(state):
    return (isinstance(state, dict) and set(state) == {"state_version", "used", "ceiling"}
            and all(natural(v) for v in state.values()) and state["used"] <= state["ceiling"])


def predicate(state, amount):
    return state["used"] + amount <= state["ceiling"]


def required_decision(record, report_valid, supplied, amount, mode, state):
    """Independent normative decision; never consumes the observed admit/reject."""
    if record is None:
        return "cannot_establish", "CHECK_MISSING"
    if supplied != record:  # M5: exact checked coordinates, result and check identity
        return "reject", "CHECK_STATE_IDENTITY_MISMATCH"
    if amount != record["amount"]:  # M6: request scope
        return "reject", "REQUEST_SCOPE_MISMATCH"
    if not report_valid:
        return "reject", "CHECK_RESULT_MISREPORTED"
    if not record["predicate_result"]:  # M4: a failed CHECK is not old-PASS authority
        return "reject", "EVENT_PREDICATE_FALSE"
    if mode == "UNBOUND":
        if record["checked_state_version"] != state["state_version"]:  # M1
            if not predicate(state, amount):
                return "reject", "STALE_UNBOUND_CONSUMPTION"
            return "cannot_establish", "UNBOUND_CHANGED_STATE"
        return "admit", "UNCHANGED_STATE_PASS"
    if mode == "VERSION_BOUND":
        if record["checked_state_version"] != state["state_version"]:  # M2/M7
            return "reject", "CHECKED_VERSION_NOT_CURRENT"
        return "admit", "CHECKED_VERSION_CURRENT"
    if predicate(state, amount):  # M3: recompute over current outcome-affecting state
        return "admit", "CURRENT_PREDICATE_TRUE"
    return "reject", "CURRENT_PREDICATE_FALSE"


def evaluate(case):
    try:
        return _evaluate(case["inputs"])
    except (ValueError, KeyError, TypeError):
        return result("cannot_establish", "cannot_establish", "none", "cannot_establish",
                      None, None, ["INVALID_HISTORY"], [])


def result(event, consumption, observed, required, checked, current, reasons, results):
    return {"event_time_status": event, "consumption_time_status": consumption,
            "observed_consumption_outcome": observed, "required_consumption_outcome": required,
            "checked_state_version": checked, "current_state_version": current,
            "reason_codes": sorted(reasons), "observed_results": results}


def _evaluate(data):
    require(isinstance(data, dict) and set(data) == {"initial", "history"})
    require(state_valid(data["initial"]))
    state = data["initial"].copy()
    history = data["history"]
    require(isinstance(history, list) and bool(history))
    record = None
    report_valid = False
    event = "cannot_establish"
    observations = []
    for index, step in enumerate(history):
        require(isinstance(step, dict))
        op = step["op"]
        if op == "CHECK":
            require(set(step) == {"op", "check_id", "amount", "predicate_result"})
            require(record is None and isinstance(step["check_id"], str) and bool(step["check_id"]))
            require(natural(step["amount"]) and type(step["predicate_result"]) is bool)
            computed = predicate(state, step["amount"])
            record = {"check_id": step["check_id"], "checked_state_version": state["state_version"],
                      "checked_used": state["used"], "checked_ceiling": state["ceiling"],
                      "amount": step["amount"], "predicate_result": computed}
            report_valid = step["predicate_result"] == computed
            event = "satisfied" if report_valid else "violated"
            observations.append({"op": op, "check": record.copy(),
                                 "reported_predicate_result": step["predicate_result"]})
        elif op == "STATE_TRANSITION":
            require(set(step) == {"op", "state"} and state_valid(step["state"]))
            require(step["state"]["state_version"] == state["state_version"] + 1)
            state = step["state"].copy()
            observations.append({"op": op, "state": state.copy()})
        elif op == "CONSUME":
            require(index == len(history) - 1)
            require(set(step) == {"op", "mode", "amount", "check", "observed_outcome"})
            require(step["mode"] in MODES and natural(step["amount"]))
            require(step["observed_outcome"] in {"admit", "reject"})
            supplied = step["check"]
            if supplied is not None:
                require(isinstance(supplied, dict) and set(supplied) == {
                    "check_id", "checked_state_version", "checked_used", "checked_ceiling", "amount", "predicate_result"})
                require(isinstance(supplied["check_id"], str) and bool(supplied["check_id"]))
                require(all(natural(supplied[k]) for k in ("checked_state_version", "checked_used", "checked_ceiling", "amount")))
                require(type(supplied["predicate_result"]) is bool)
            required, reason = required_decision(record, report_valid, supplied, step["amount"], step["mode"], state)
            observed = step["observed_outcome"]
            reasons = [reason]
            if event == "satisfied":
                reasons.append("EVENT_TIME_EVALUATION_CORRECT")
            elif event == "violated":
                reasons.append("EVENT_TIME_RESULT_MISMATCH")
            if required == "cannot_establish":
                consumption = "violated" if observed == "admit" else "cannot_establish"
            else:
                consumption = "satisfied" if observed == required else "violated"
            if consumption == "violated":
                reasons.append("CONSUMPTION_OUTCOME_MISMATCH")
            observations.append({"op": op, "mode": step["mode"], "amount": step["amount"],
                                 "supplied_check": supplied, "outcome": observed})
            return result(event, consumption, observed, required,
                          record["checked_state_version"] if record else None,
                          state["state_version"], reasons, observations)
        else:
            raise ValueError("unknown operation")
    return result(event, "cannot_establish", "none", "cannot_establish",
                  record["checked_state_version"] if record else None, state["state_version"],
                  ["CONSUME_MISSING"], observations)


def load_cases(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    require(document["profile"] == PROFILE and bool(document["cases"]))
    cases = document["cases"]
    require(len({c["case_id"] for c in cases}) == len(cases))
    return cases


def main():
    cases = load_cases(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("vectors.json"))
    results = []
    for case in cases:
        actual = evaluate(case)
        results.append({"case_id": case["case_id"], "result": actual, "reproduced": actual == case["expected"]})
    counts = {axis: {s: sum(r["result"][axis] == s for r in results)
                     for s in ("satisfied", "violated", "cannot_establish")}
              for axis in ("event_time_status", "consumption_time_status")}
    print(json.dumps({"results": results, "counts": counts, "total": len(cases),
                      "reproduced": sum(r["reproduced"] for r in results)}, sort_keys=True, indent=2))
    return 0 if all(r["reproduced"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
