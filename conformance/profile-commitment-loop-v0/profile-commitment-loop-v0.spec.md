# profile-commitment-loop.v0

The **end-to-end loop**, chaining [`profile-amendment-v0`](../profile-amendment-v0/) (amendment end) and
[`verdict-profile-binding-v0`](../verdict-profile-binding-v0/) (resolution end) over the *same* task+escrow,
so the seam between them is a **mechanical check, not a shared constant**.

## Why

The two sub-suites each correctly test their own predicate in isolation, and both happen to reference the
same profile commitment — but that equality lived only in prose. A shared constant maintained by hand is
exactly the side-channel reference the family exists to kill, one level up in our own fixtures: change the
profile in one suite and not the other and both stay green while the loop is silently broken. (Raised by
@babyblueviper1 on recompute-kit #41: should a vector run both gates end-to-end, feeding a `permitted`
amendment's resulting commitment as the `bound` verdict's expected value?)

## Construction

The gate imports the two **shipped** gates (`amendment_gate.py` / `verdict_binding_gate.py`, and their
`.reference.mjs` twins) and composes them — it does not reimplement, so it cannot drift from what #40 and
#41 actually enforce:

1. Run the amendment gate over the amendment-side inputs → `effective_profile_commitment`.
2. Feed **that computed value** (never a hand-set constant) as the resolution gate's
   `task_effective_profile_commitment`, and run it over the verdict.
3. `loop_status` is `closed` iff the amendment is a **permitted** transition AND the verdict is **bound**
   to that computed effective profile; otherwise `open`, fail closed.

Because the resolution gate's own profile-match predicate is `verdict_core.effective == task_effective`, and
`task_effective` is now the amendment's *computed* output, that predicate **is** the seam check.

## Composition invariant

```
profile_transition(task).effective_profile_commitment == verdict.core.effective_profile_commitment
```

`closed` means Pavlo Tvardovskyi's `task.profile_commitment == verdict.profile_commitment` holds with both
ends cryptographic **and mechanically chained**, not asserted across two fixtures.

## Vectors

Six, in `profile-commitment-loop-v0.vectors.json` — one `closed`, five `open`, one per failure mode:

- `closed` — authorized A→B (both co-sign) + verdict commits exactly B + signed → loop closes
- `open-bare-swap` — unauthorized swap: amendment fails closed to A, verdict commits B → seam mismatch → open
- `open-verdict-wrong-profile` — permitted A→B, but the verdict resolves under the old profile A → seam
  mismatch → open (this is the case a shared-constant setup would miss; the computed chaining catches it)
- `open-verdict-unsigned` — permitted A→B, right profile, but the resolver did not sign this verdict core → open
- `open-verdict-profile-omitted` — permitted A→B, verdict carries no `effective_profile_commitment` → open
- `open-amendment-unresolved-verdict-bound` — refused A→B (only one party co-signs) so A stays effective;
  the verdict then *correctly* resolves under A and is signed → `resolution_status` = `bound`, but
  `transition_status` = `unresolved` → loop `open`. The one vector where the resolution end is bound while
  the amendment end is not permitted, so it makes the `transition_status == "permitted"` conjunct
  load-bearing (raised by @Pavlentyy82, seconded by @babyblueviper1 on #42).

Reproduced byte-for-byte by `loop_gate.py` and `profile-commitment-loop-v0.reference.mjs` (bun/node), each
composing the shipped gates; each reds on a refuted vector, and a gate mutated to feed the verdict's own
claimed profile (the shared-constant bug) flips exactly `open-verdict-wrong-profile` to a false `closed` —
so the seam is demonstrably load-bearing.

**Both conjuncts of `closed` are exercised.** `closed` is `transition_status == "permitted" AND
resolution_status == "bound"`. A mutant dropping the *resolution* conjunct is caught by
`open-verdict-wrong-profile` (as above). A mutant dropping the *transition* conjunct
(`closed = resolution_status == "bound"` alone) is caught by exactly one vector,
`open-amendment-unresolved-verdict-bound`, which flips to a false `closed`; the other five stay green
under that mutation. Neither conjunct is merely present — each is proven to red a refuted vector.

**Which vector isolates the seam.** That same mutation also drifts the resolution-side fields on
`open-bare-swap`, but its `loop_status` does not move: its amendment side already refuses
(`transition_status` stays `unresolved`, which forces `closed=false` regardless of what the resolution
side reports), so the drift is masked there. `open-verdict-wrong-profile`, where the amendment is
permitted, is therefore the only vector whose `loop_status` isolates the seam predicate. (Caught by
@babyblueviper1 on #42.)

## Scope

Checks the composition binding, not signature cryptography (inherited from the two sub-suites: an
authorization/resolver signature is "bound" iff `signed_digest` equals the relevant content-address).
