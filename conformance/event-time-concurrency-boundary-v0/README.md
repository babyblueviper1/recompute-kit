# Event-time and concurrent admission boundary v0

Profile: `event_time_concurrency_boundary.v0`. A generic, deterministic trace
checker and falsifiable companion spec. **No proven live bug** is the correct
current claim. These synthetic schedules are not observations of a deployment.

## Three distinctions

```text
PERIODIC/AUDIT PASS != EVENT-TIME AUTHORIZATION
EVENT-TIME CHECK   != ATOMIC CHECK-AND-WRITE
IDEMPOTENCY       != ATOMICITY
```

EXACTLY-ONCE OBSERVABLE ADMISSION requires more than duplicate detection.
Identity-based replay and exclusion of conflicting distinct requests are separate
obligations. This finite safety model does not establish delivery, eventual
admission, crash recovery, durability, or exactly-once behavior in a live system.

## Independent invariants

**A -- event-time enforcement.** For every newly committed event E, its safety
predicate MUST have been evaluated on the event path using the policy state
applicable to E. An earlier periodic/audit PASS alone MUST NOT authorize E.
In this model the predicate is `request.amount <= policy.ceiling`. An event
check records a concrete `policy_version`; that version must still be current
at commit and the predicate must have passed. A policy transition after CHECK
invalidates that authorization even if the new ceiling would also allow E.
This conservative rule requires re-evaluation, not a vague freshness flag.

**B -- atomic admission under concurrency.** Event-time evaluation does not
establish atomicity. A newly committed protected transition must either compare
its read `expected_version` with current `state_version` at the indivisible modeled
CAS step, or operate under declared exclusion covering the entire read-through-
completion interval for this state domain. A committed CAS observation with unequal
versions violates B. A concurrent unprotected WRITE violates B. Declared exclusion
contradicted by overlapping intervals also violates B, even if the overlap happens
not to produce a second commit in that schedule.

These are separate predicates. `policy_version` identifies semantic authorization
state; `state_version` identifies the protected admission state. C1 keeps policy
unchanged while two admissions conflict over a protected version. C2 changes policy
without consuming the protected admission version, so a correctly compared CAS
can still carry invalid semantic authorization. All semantic inputs in this small
model are in the versioned policy plus immutable request. Real integrations must
identify and bind their actual dependencies; two counters alone do not do that.

## Deterministic trace contract

`vectors.json` supplies one protected state domain per case, initial
`state_version`, `policy_version`, and `ceiling` (nonnegative integers), immutable
requests keyed by writer name, a discipline, an idempotency setting, and an ordered
schedule. No wall-clock threads, network, database, locks, or timing guesses.
Both clocks are monotonic and cannot reset/wrap in this model. Distinct domains,
ABA/version reuse, crashes and incomplete external histories are outside it.

| Operation | Recomputed meaning |
| --- | --- |
| `AUDIT(writer)` | Store this request's predicate result and policy version before its attempt; supplied-model authenticity is assumed, not cryptographically verified. |
| `POLICY(policy_version, ceiling)` | Advance policy version by exactly one and set its ceiling. Does not advance admission state. |
| `READ(writer, expected_version)` | Begin an attempt; the supplied expected version must equal the modeled current version. Remains active until WRITE/CAS completion. |
| `CHECK(writer, EVENT_REEVALUATED)` | Recompute predicate on the current policy, retaining its version and result. |
| `CHECK(writer, PERIODIC_PASS_ONLY)` | Consume the earlier AUDIT result for the same writer; this cannot authorize a commit. |
| `WRITE/CAS(writer, outcome, index)` | Observe a completion: `commit`, `reject`, or `replay`. These are supplied observations, not decisions made by a production writer. |

Each writer has one attempt; a retry is another writer entry carrying the same
canonical capture reference. A commit assigns the next index starting at zero
and advances observed state by one. Even an unsafe commit is retained in the
observed history: the checker reports the violation rather than repairing history.
Thus a race can have two effects (7 -> 8 -> 9) both based on expected version 7.
Rejection and replay do not advance state. Rejections need no receipt index.
The safety model permits conservative rejection; it makes no availability claim.

For `idempotency: true`, request identity is full SHA-256 of the ASCII JSON array
`["event_time_concurrency_boundary.v0", canonical_capture_ref]` using
`ensure_ascii=True` and separators `(',', ':')`. This is this companion's local,
unambiguous encoding, not the historical profile's truncated fixture encoding.
The same capture reference must carry the same amount. Capture references and
their content binding are trusted fixture inputs, not authenticated here.
The first commit creates an immutable identity -> index mapping. Replay must
return that exact existing index and create no transition. A second commit with
the same identity violates idempotency even if its protected version is current.
Distinct identities can preserve every mapping while violating B (B6).
`idempotency: false` gives `not_applicable`, never an inferred replay guarantee.

`SINGLE_WRITER` and `SERIALIZED` both require nonoverlapping active intervals.
Concurrency overlap is scoped to each attempt's active READ -> completion interval.
A new READ marks itself and every currently active attempt as overlapped; an attempt
starting after all prior attempts finish starts nonoverlapped. Prior overlap elsewhere
in the supplied history does not by itself prove that a later attempt was concurrent.
An actually overlapping unprotected WRITE remains a violation; an isolated one under
`UNSPECIFIED` remains `cannot_establish` without CAS or declared serialization evidence.
Success under either declared discipline is labeled **SAFE UNDER THE MODELED SERIALIZATION ASSUMPTION**
(`SAFE_UNDER_MODELED_SERIALIZATION_ASSUMPTION` in output). Single-writer admission
may suffice under a declared single-writer model, but that assumption is part of
the trusted operating model and MUST NOT be silently generalized to concurrent
writers. One observed unprotected writer under `UNSPECIFIED` gives
`cannot_establish`, not a concurrency guarantee. CAS traces can establish B for
the supplied schedule without a serialization declaration. Rejection-only
schedules establish no committed violation, not implementation capability.

## Independent outputs and conformance grading

Every case returns these independent fields:

```json
{
  "event_time_status": "satisfied|violated|cannot_establish",
  "concurrency_status": "satisfied|violated|cannot_establish",
  "idempotency_status": "satisfied|violated|not_applicable|cannot_establish",
  "admission_result": "admit|reject|cannot_establish",
  "reason_codes": [],
  "transition_count": 0,
  "final_state_version": 7,
  "observed_results": []
}
```

`admission_result` is the normative judgment of the supplied admission history,
not a rewrite of its observed completions. Any violated invariant yields `reject`;
otherwise incomplete evidence yields `cannot_establish`; otherwise at least one
commit/replay yields `admit`, and an entirely rejected schedule yields `reject`.
`observed_results` preserves each actual trace outcome and returned index.
The separate status fields remain authoritative for the two different questions.

Within each axis, a witnessed violation outranks missing evidence. Unfinished
attempts or unattempted declared writers prevent an unqualified success. A rejected
attempt without an event check gives `cannot_establish` on A. Replay inherits the
history's earlier authorization assessment and performs no new authorization.
Malformed/contradictory structure (unknown operation, false READ coordinate,
missing required field, etc.) gives `INVALID_TRACE` and all axes
`cannot_establish`; such input is not evidence of an invariant violation.
Reasons are sorted for deterministic byte output.

Conformance PASS means exact equality with the entire expected result object.
An unsafe history MUST be judged unsafe; correctly detecting it is a reproduced
vector, not a conformance failure. In the case descriptions below, FAIL means an
invariant is violated; the CLI still succeeds when it reproduces that FAIL.

| Vectors | Required distinction |
| --- | --- |
| A1 / A2 / A3 / A4 | Current true check admits; stale periodic authority fails; current false check safely rejects; valid old PASS without event establishment fails. |
| B1 / B2 / B3 / B4 | Declared single writer; overlapping non-atomic writes; CAS rejects stale second writer; declared serialized writers each observe current version. |
| B5 / B6 | Same-identity replay returns existing index; distinct identities with intact mappings still race. |
| C1 | A satisfied, B violated: event-time checks do not imply atomicity. |
| C2 | A violated, B satisfied: atomic writes do not imply semantic validity. |
| C3 | Both satisfied, exactly one protected transition in this schedule. |
| D1-D3 | Missing event check, stale committed CAS, falsely declared serialization. |
| D4-D6 | Undeclared single writer, invalid operation, incomplete schedule. |
| D7-D11 | Policy changes after CHECK, changed replay receipt, duplicate identity transition, committed false predicate, invalid READ coordinate. |
| D12 | Earlier safe CAS overlap does not taint a later isolated unprotected WRITE: historical overlap != current attempt overlap; insufficient evidence != proven concurrent-write violation. |

## Mutation falsifiability

`mutation_check.py` applies seven one-site source mutations in isolated namespaces.
M1-M6 have required negative killers and must wrongly upgrade the killer's named
axis from `violated` to `satisfied`; M7 must wrongly classify D12's concurrency
axis from `cannot_establish` to `violated`. Each must preserve the transition witness. All
seven fully safe control vectors (including A3's correct rejection) must still
match their complete expected results. A crash, unapplied patch, merely unknown
result, broken positive control, or mismatch on some unrelated vector is not a kill.
Mutation failures return nonzero. The checker has no mutation-mode switch.

| Mutant | Mistake | Required killer |
| --- | --- | --- |
| M1 | Earlier periodic PASS accepted as authority | A2_PERIODIC_PASS_BECOMES_STALE |
| M2 | Required event re-evaluation omitted | D1_EVENT_CHECK_REMOVED |
| M3 | Atomic version comparison omitted | D2_STALE_CAS_COMMIT |
| M4 | Idempotency substituted for atomicity | B6_DISTINCT_REQUEST_RACE |
| M5 | Second writer allowed after version advanced | D2_STALE_CAS_COMMIT |
| M6 | Serialization assumed despite overlapping writers | D3_SERIALIZATION_OVERLAP |
| M7 | Nonoverlapping attempt treated as concurrent | D12_PRIOR_OVERLAP_DOES_NOT_TAINT_LATER_WRITER |

M3 and M5 deliberately share the smallest stale-commit witness but change the
checker differently (no comparison versus a comparison admitting older versions).
These mutate the trace oracle's enforcement, not any existing profile or writer.

## Exact relationship to existing profiles

Inspected base: `trustless-ai/recompute-kit` at
`f5a25bd6bbf555c710d63915d4e5092548e3702c` (fetched `origin/main`).

- [`conformance/pq-recovery-classes-v0/`](https://github.com/trustless-ai/recompute-kit/tree/f5a25bd6bbf555c710d63915d4e5092548e3702c/conformance/pq-recovery-classes-v0):
  `README.md` section "Terminality is a standing binding-path constraint, not an
  auditor snapshot", `recovery_check.py::bind_gate`, and its `vectors.json`
  bind cases provide standing/event-path re-evaluation against prior terminal and
  recovery state. They do NOT by themselves establish atomic concurrent admission.
  The original README labels this vector-first/pre-implementation.
- [`conformance/captured-admission-v0/`](https://github.com/trustless-ai/recompute-kit/tree/f5a25bd6bbf555c710d63915d4e5092548e3702c/conformance/captured-admission-v0):
  `README.md` section "Idempotency", `admission_check.py::idempotency`, and
  `vectors.json` cases `IDEMPOTENCY_*` provide deterministic admission identity,
  immutable identity -> index mapping, idempotent replay, duplicate/conflict
  detection and lookup-or-create shape. The explicit evidence boundary says they
  do NOT enforce atomicity at write time. This companion does not upgrade that claim.

Repository-wide search at that base for compare-and-swap, CAS, idempotent,
idempotency, nonce, version, sequence, single writer, atomic, concurrency,
concurrent, admission, bind_gate, replay, exactly once, lookup-or-create,
append-only and transaction found no existing profile giving this joint mechanical
distinction. `captured-admission-v0-review-profile` extends duplicate detection;
`predicate-conformance-v0` tests declared predicate/run bindings, not admission
interleavings. This companion reuses the conceptual shapes only; it imports no
checker code and changes neither frozen profile, its vectors, nor its results.

## Verification and evidence boundary

From repository root:

```sh
python3 conformance/event-time-concurrency-boundary-v0/boundary_check.py conformance/event-time-concurrency-boundary-v0/vectors.json
python3 conformance/event-time-concurrency-boundary-v0/mutation_check.py
python3 tools/run_conformance.py
git diff --check
```

The first command checks all 25 complete expected results. `suite.json` registers
both conformance and mutation checks using the existing multi-check convention.
Vector and spec hashes are mechanically SHA-256 pinned. Checker and mutation
source pins are supplied too; the canonical runner validates vectors/spec pins,
but does not currently validate arbitrary checker metadata pins. To validate all
four local pins explicitly (run inside this profile directory):

```sh
python3 -c "import hashlib,json,pathlib; m=json.loads(pathlib.Path('suite.json').read_text()); pins=[m['spec'],m['checker'],m['mutation_checker']]+[c['vectors'] for c in m['checks']]; bad=[p['path'] for p in pins if hashlib.sha256(pathlib.Path(p['path']).read_bytes()).hexdigest()!=p['sha256']]; print({'mismatches':bad}); raise SystemExit(bool(bad))"
```

A conformance checker can prove the required state-machine behavior over supplied
schedules/vectors; it does NOT establish that a production storage engine actually
provides transactions/CAS/serialization. This is finite trace checking, not an
exhaustive proof over all schedules and not a linearizability proof. CAS is an
indivisible step in the supplied model; this checker does not implement a
production CAS, transaction manager, or concurrent writer. No particular database
or API is required. Actual production exclusion, complete history, policy update
ordering, identity authenticity and persistence must be established separately.
No production bind_gate safety or live exactly-once claim is made. No proven live
bug, exploit, or deployment-level safety conclusion follows from these vectors.
