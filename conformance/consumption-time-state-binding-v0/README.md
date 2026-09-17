# Consumption-time state binding v0

Profile: `consumption_time_state_binding.v0`.

```text
EVENT-TIME PASS != CONSUMPTION-TIME STATE VALIDITY
EVENT_TIME_VALID != VALID_AT_CONSUMPTION
```

The profile makes stale consumption of a previously valid, state-dependent
authorization mechanically falsifiable. It verifies supplied finite deterministic
histories only. No proven live bug is claimed.

## State, predicate and checked identity

One protected capacity domain has `{state_version, used, ceiling}`. All values
are nonnegative integers (JSON booleans are not integers), with `used <= ceiling`.
The request is a nonnegative integer `amount`. The predicate is:

```text
used + amount <= ceiling
```

CHECK records the exact tuple `{check_id, checked_state_version, checked_used,
checked_ceiling, amount, predicate_result}`. The checker computes this tuple from
the supplied state history; CONSUME carries a receipt to compare against it.
There is no freshness boolean or caller-selected substitute for these coordinates.

The history has at most one CHECK and at most one CONSUME. CONSUME, if present,
must be last. These narrow histories test one authorization's consumption, not a
general ledger, retry protocol, concurrent writer or exactly-once implementation.

| Operation | Supplied fields and recomputation |
| --- | --- |
| CHECK | `check_id`, `amount`, reported `predicate_result`; independently recompute the predicate and retain the exact checked tuple. |
| STATE_TRANSITION | Full replacement `state`; require well-formed capacity and exactly `previous state_version + 1`. This is a completed transition before the next operation. |
| CONSUME | `mode`, `amount`, supplied `check` tuple or null, and `observed_outcome` (`admit` or `reject`); derive the required decision independently of that observation. |

Every STATE_TRANSITION advances version, including value restoration. Releasing
capacity or changing a ceiling is allowed if the resulting state is well formed.
The fixture stipulates that the transition is legitimate; the checker proves
structural version progression, not its real-world authority. No version wrap or
reuse is allowed. An observed CONSUME admit does not itself alter capacity here;
all state changes are explicit STATE_TRANSITION operations. There is no hidden
second writer or asynchronous side effect.

## Required consumption decisions

Before applying any mode, the checker requires an existing CHECK, exact receipt
equality to the recomputed tuple, the same request amount, a truthful reported
CHECK result, and an original PASS. A failed CHECK is never old-PASS authority,
even if a later state makes its predicate true. Obtaining new authority would
require a new CHECK in a new history; REEVALUATE here only refreshes a prior PASS.

**VERSION_BOUND** requires current version equal to checked version. Version
inequality requires rejection, even if current values would satisfy the predicate
(S6) or have returned to their old values (S11). Under this model's rule that all
outcome-affecting transitions advance version, equality preserves the checked
state. This is a conservative policy, not a proof of version authenticity.

**REEVALUATE** recomputes the full predicate using current `used`, current `ceiling`
and the bound amount. It may admit despite version inequality when the predicate
remains true (S5); it rejects when the current predicate is false (S4).
Neither policy is universally better. They establish different policies.

**UNBOUND** describes attempted reuse of the old PASS without consumption-time
binding or re-evaluation. The offline oracle uses the complete supplied history
to assess it: unchanged version permits admission; changed version with a false
current predicate requires rejection (`STALE_UNBOUND_CONSUMPTION`). If state
changed but the predicate is still true, the unbound attempt does not establish
the required consumption-time evidence (`cannot_establish`). S15's unchanged
control is a trace-relative conclusion, not a general guarantee about an unbound
implementation. The oracle's recomputation does not mean the consumer did so.

These mode decisions are deterministic within this profile. An observed outcome
that differs from a known required outcome violates that mode's conformance,
including a false rejection. This is not a general availability/liveness claim.
If required authorization cannot be established, an observed admit violates the
boundary; an observed reject retains `cannot_establish` rather than fabricating
missing evidence. Missing CHECK gives `cannot_establish` and never a safe admit.

## Independent result axes

The CLI wraps each full result with `case_id` and an exact-match `reproduced` grade.
The result contains:

```json
{
  "event_time_status": "satisfied|violated|cannot_establish",
  "consumption_time_status": "satisfied|violated|cannot_establish",
  "observed_consumption_outcome": "admit|reject|none",
  "required_consumption_outcome": "admit|reject|cannot_establish",
  "checked_state_version": 7,
  "current_state_version": 8,
  "reason_codes": [],
  "observed_results": []
}
```

`event_time_status` grades whether the recorded CHECK truthfully evaluated the
predicate on its then-current state. An honestly reported false predicate can
satisfy event-time evaluation while requiring rejection (S7). S13 demonstrates
an actual event-time violation: the reported CHECK claims PASS for a false
predicate. Consumption then correctly rejects that misreported result.

`consumption_time_status` grades the observed consumption against the required
mode decision and its evidence. The required decision never reads the supplied
observed outcome. Bad admits remain in `observed_results`; they are not rewritten
into rejects. A reproduced violation is a passing conformance vector, not a
passing authorization. Reasons are sorted; no timestamps or random values occur.

A missing CONSUME returns observed `none`, consumption/required `cannot_establish`,
and `CONSUME_MISSING`, retaining the valid CHECK and state coordinates if known.
Malformed history (such as a nonadvancing state version) returns `INVALID_HISTORY`,
both statuses `cannot_establish`, null coordinates and no assessed observations.
Well-formed but tampered receipt coordinates are a determinate rejection, not
silently trusted state identity (S9). Unknown operations/modes are not accepted.

## Corpus and central reviewer case

S2 is exactly this fully serialized history:

```text
initial: v7, used=0, ceiling=10
CHECK B amount=6: 0+6<=10 -> PASS; retain exact v7 tuple
STATE_TRANSITION completes: v8, used=6, ceiling=10
CONSUME old tuple with UNBOUND, observed admit
current predicate: 6+6<=10 -> false
```

Result: event-time `satisfied`, consumption-time `violated`, observed `admit`,
required `reject`, checked version 7/current version 8. Reasons:
`EVENT_TIME_EVALUATION_CORRECT`, `STALE_UNBOUND_CONSUMPTION`,
`CONSUMPTION_OUTCOME_MISMATCH` (emitted in sorted order).
No concurrent writer is present at consumption; there are no overlapping
READ/WRITE intervals, CAS failures, or serialization ambiguity. A perfectly
serialized consumer can still consume semantically stale authority.

| Cases | Discrimination |
| --- | --- |
| S1 | Unchanged state, VERSION_BOUND PASS admits. |
| S2 | Old event PASS with stale UNBOUND admit violates consumption validity. |
| S3 / S4 | Same changed state; VERSION_BOUND and REEVALUATE safely reject. |
| S5 / S6 | Changed state still satisfies amount 2: REEVALUATE admits; VERSION_BOUND conservatively rejects. |
| S7 and its UNBOUND/VERSION_BOUND variants | An original false CHECK cannot authorize in any mode; the REEVALUATE case even restores sufficient capacity first. |
| S8 | Missing CHECK cannot establish authority. |
| S9 / S10 | Tampered checked state / wrong request amount cannot reuse a PASS. |
| S11 | used=0 at v7 -> used=4 at v8 -> used=0 at v9; equal values are not the same state identity. |
| S12 / S13 | Nonadvancing version is malformed; a false predicate reported as PASS violates event-time evaluation. |
| S14 / S15 / S16 | Missing consume; unchanged UNBOUND control; changed-but-true UNBOUND evidence remains insufficient. |

## Mutation evidence

Seven exact one-site source mutations have named required killers. A kill requires
the killer's required decision to change specifically from `reject` to `admit`,
with its event-time status, checked/current versions and full observed history
unchanged. Crashes, unapplied patches, unknown results and unrelated mismatches
are not kills. Mutated source runs in isolated namespaces; no profile file is edited.

The three named successful-admission controls S1, S5 and S15 cover all three modes
and must retain their complete expected results under every mutant. S3/S4/S7/S11
are rule-specific rejection witnesses, not those positive controls: removing a
rule must incorrectly change their required decision even though their supplied
observed behavior remains rejection. Thus no mere broken-control result is counted
as a kill. The baseline must first reproduce every full expected case, including
all safe rejection cases. The harness exits nonzero unless all mutations are killed.

| Mutant | Required killer |
| --- | --- |
| M1_OLD_PASS_IS_CONSUMPTION_AUTHORITY | S2_STALE_PASS_AFTER_STATE_CHANGE_UNBOUND |
| M2_VERSION_BINDING_REMOVED | S3_VERSION_BOUND_REJECTS_STALE |
| M3_REEVALUATION_REMOVED | S4_REEVALUATE_REJECTS_STALE_FALSE |
| M4_EVENT_FALSE_CAN_BE_CONSUMED | S7_EVENT_TIME_FALSE |
| M5_CHECK_STATE_IDENTITY_NOT_BOUND | S9_CHECK_STATE_COORDINATE_TAMPER |
| M6_REQUEST_SCOPE_NOT_BOUND | S10_WRONG_REQUEST_REUSE |
| M7_STATE_VALUE_EQUALITY_TREATED_AS_STATE_IDENTITY | S11_ABA_VALUE_EQUALITY_NOT_STATE_IDENTITY |

## Relationship to PR #45

Stack base: `93946a40bd8e16312c274b6a5bc4d0773aaa44a8` in
`trustless-ai/recompute-kit`, the exact repaired head of
[Draft PR #45](https://github.com/trustless-ai/recompute-kit/pull/45).
The existing profile is
[`conformance/event-time-concurrency-boundary-v0/`](https://github.com/trustless-ai/recompute-kit/tree/93946a40bd8e16312c274b6a5bc4d0773aaa44a8/conformance/event-time-concurrency-boundary-v0).
It establishes these mechanically falsifiable distinctions over its supplied schedules:

```text
PERIODIC PASS != EVENT-TIME AUTHORIZATION
EVENT-TIME CHECK != ATOMIC CHECK-AND-WRITE
IDEMPOTENCY != ATOMICITY
```

This new profile establishes the additional distinction
`EVENT-TIME PASS != CONSUMPTION-TIME STATE VALIDITY`. It does NOT supersede PR #45,
does NOT repair PR #45, and does NOT imply PR #45 was incorrect. It adds a third
independent boundary: binding a prior event-time authorization to its later
consumption state. All PR #45 files, vectors and results remain unchanged.

The reviewer observation is correct: PR #45's event predicate is equivalent to
`amount <= ceiling`. Its truth does not depend on mutable admission state. PR #45
checks policy changes and protected-version admission separately, but cannot
falsify another completed admission changing this predicate's truth after CHECK.
This profile intentionally introduces `used + amount <= ceiling` and explicit
checked state identity. No old semantic claim is retroactively changed.

Before implementation, repository-wide searches at that stack base and main
`f5a25bd6bbf555c710d63915d4e5092548e3702c` found no existing mechanical corpus for
this exact mutable-capacity consumption relation. Search terms included
consumption-time/consumption time, state binding, state_version, checked_state,
stale authorization/receipt, current state, authorization version, re-evaluate,
reevaluate, cumulative ceiling, capacity, admission state and ABA. The closest
surface was PR #45's policy-version check; its `used`-independent predicate is the
specific scope difference, not evidence of a defect in that profile.

## Verification and claim limits

From repository root (repeat the first two commands with `python3 -O`):

```sh
python3 conformance/consumption-time-state-binding-v0/binding_check.py conformance/consumption-time-state-binding-v0/vectors.json
python3 conformance/consumption-time-state-binding-v0/mutation_check.py
python3 tools/run_conformance.py
git diff --check
```

`suite.json` registers conformance and mutation checks using the existing
multi-check convention. SHA-256 pins are mechanically generated for spec, vectors,
checker and mutation checker. The canonical runner validates vectors/spec; it does
not currently validate arbitrary checker metadata pins. Validate every local pin
from inside this directory with:

```sh
python3 -c "import hashlib,json,pathlib; m=json.loads(pathlib.Path('suite.json').read_text()); pins=[m['spec'],m['checker'],m['mutation_checker']]+[c['vectors'] for c in m['checks']]; bad=[p['path'] for p in pins if hashlib.sha256(pathlib.Path(p['path']).read_bytes()).hexdigest()!=p['sha256']]; print({'mismatches':bad}); raise SystemExit(bool(bad))"
```

This profile does NOT prove production CAS, production locking, transaction
isolation, linearizability, serialized writer enforcement, live exactly-once,
blockchain atomicity, state source authenticity, state_version authenticity,
complete production state dependencies, live authorization correctness, or any
exploitable production bug. Receipt consistency is relative to supplied histories;
it is not signature verification or independently resolved state provenance.
Mode evaluation is one modeled operation, not a claim that real re-evaluation and
consumption cannot be separated by another state change. This finite model has no
production storage engine, transaction API, blockchain semantics or scheduler.
