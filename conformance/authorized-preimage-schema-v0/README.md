# Authorized preimage schema v0

```text
SELF-CONSISTENT PREIMAGE != AUTHORIZED PREIMAGE SCHEMA
```

A proof can publish the field list it used to build a digest. A verifier can recompute that digest
perfectly, the signature can be valid, and the proof can still be under-bound: if the declared list
is a subset of what its policy version registered, the digest recomputes cleanly while a field that
policy requires (for example an action-binding hash) was never committed. The hash is correct, the
proof is self-consistent, and the promoted claim ("this decision is bound to its action") is false.

This profile pins the missing relation. A verifier must establish that the **declared field set is
registered for the proof's own policy version** before it treats a clean recompute as evidence, and it
must report the dimensions separately instead of one scalar "verified". A fourth dimension,
`registered_set_completeness_status`, is reported so the profile states its own epistemic boundary
instead of leaving it in prose.

Status: `authorized_preimage_schema.v0`, vectors + checker + mutation evidence. Shaped like
`consumption-time-state-binding-v0` (#46).

## What this profile does not establish

*(Written first, before the checker and vectors: these are the claims this profile is not allowed to make.)*

A reference set is its maintainer's claim about which fields a decision commits to. A verifier can
recompute against it and can report who holds the authority, but it cannot establish that the set is
complete or correct, and nothing inside the producer's boundary can.

- **Completeness and correctness of the registry are not established.** The snapshot is a producer-side
  claim. `registry_sha256` pins its content, not its truthfulness. This is now exposed mechanically as
  `registered_set_completeness_status`, which is `cannot_establish` on every vector and is **non-gating**:
  an `accept` means "this proof conforms to the registered preimage schema", never "the registered
  schema is semantically complete" (`AUTHORIZED PREIMAGE SCHEMA != COMPLETE SEMANTIC COMMITMENT SCHEMA`).
  Because a constant is emitted correctly by an implementation that computes nothing, the mutation suite
  has a mutant that claims it (`M13`) and one that promotes the non-claim to a failure (`M14`); both must
  be killed.
- **Registry authority is relayed, not recomputed.** A verifier that returns `authorized` has recomputed
  the hash and checked the signature; it has *relayed* that the set is registered. Reports should keep
  those two apart (the reference implementation does, see below).
- **Signature validity is not authority.** A valid signature under a key the verifier trusts says who
  signed, not that the signed field set is the right one.
- **Two implementations agreeing is not independent review.** The cross-check below compares this
  checker with the issuer's production verifier: independent code paths, but **both written by the same
  party**, so they share one author's reading of the rule. A third implementation by someone else is the
  test that would actually stress the spec, and this profile invites it.
- **The test key is not an issuer key** and proves nothing about any real issuer.
- **Canonicalization scope is normative (a conformance rule, not an implementation note).** Preimage values are
  strings, `null`, or safe integers, where RFC 8785 output equals compact sorted-key JSON. Any other value type
  makes the recompute `cannot_establish`, which gates the outcome to `reject`. An implementation of this profile
  that admits floats is **non-conformant**: RFC 8785 number serialization is ECMAScript `Number::toString`, and
  shortest-round-trip is where implementations diverge without an error, so a checker that gets one wrong reports
  a verdict, and the verdict is wrong (fail-open). `N7` and `N14` pin the rule; mutant `M18` (admits floats) must be
  killed. (Scope rule proposed by Matthew Moore on #48; a second implementation with a real RFC 8785 library may be
  stronger, and the divergence below says so.)
- **The serializer version is validated only when the proof declares it.** `canonicalization_version` is checked when it is in the declared
  field list (`N12`); a proof whose declared set omits it makes no serializer claim, and this profile recomputes with its own
  RFC 8785 subset (string, `null`, safe integer values). A proof under another serializer therefore reports `cannot_establish`, never `satisfied`.
- **Coverage is finite.** 19 cases and 18 one-site mutations show these bugs are caught, not that no
  other bug exists.
- **"19/19 reproduced" is not "19/19 agreed by an independent code path".** The expected results in
  `vectors.json` are authored by hand in `generate_vectors.py` (`EXPECTED`) from each case's stated
  purpose, and the generator fails if the checker disagrees. They are no longer produced by the checker
  under test (an earlier revision did that, so the count only showed the checker was deterministic). The
  authored table is still one author's reading of the rules; independence is what the cross-check below
  and a third implementation provide.
- **`registry_sha256` pins the serialization, not set membership.** The digest covers the canonical JSON
  including the order of registered states within a version, so two snapshots that differ only in that
  order have different digests while being semantically identical. Harmless today; it matters if the
  extraction order ever changes.

## Recompute it (no dependencies beyond Python 3)

```sh
python3 schema_check.py vectors.json   # 19/19 reproduced; exit 0
python3 mutation_check.py              # 18/18 KILLED on the intended dimension, controls preserved; exit 0
```

## What a case supplies

- a signed NIP-01 event (kind 30078) whose `content` is a JSON object carrying `decision_ref`,
  `decision_ref_preimage_fields` (the declared list), `policy_version`, and the values of the fields;
- a pinned registry snapshot (`registry`, with `registry_sha256`) mapping each policy version to its
  registered field-set states, and a `trusted_pubkey` (a published test key, see below);
- `observed_verification_outcome`: what the verifier under test returned (`accept` / `reject`).

The checker computes the **required** outcome independently and never reads the observed one.

## Four dimensions, established separately (three gate the outcome; the fourth is constant and non-gating)

Each dimension is tri-state (`satisfied` / `violated` / `cannot_establish`). `cannot_establish` is its
own answer and is never rewritten into `violated`.

| dimension | question | reason codes |
|---|---|---|
| `signature_status` | Does the BIP-340 signature verify over the NIP-01 event id, under the trusted key? | `SIGNATURE_VALID`, `SIGNATURE_INVALID`, `EVENT_ID_MISMATCH`, `UNTRUSTED_PUBKEY`, `MALFORMED_EVENT` |
| `preimage_schema_status` | Is the declared field **set** registered for the proof's own `policy_version`? | `DECLARED_SET_REGISTERED`, `DECLARED_SET_NOT_REGISTERED_FOR_VERSION`, `POLICY_VERSION_NOT_REGISTERED`, `MALFORMED_DECLARED_LIST` |
| `decision_ref_recompute_status` | Does `decision_ref` equal `sha256(JCS({name: content[name]}))` over **exactly the declared names** (absent -> `null`)? | `DECISION_REF_RECOMPUTED`, `DECISION_REF_MISMATCH`, `UNSUPPORTED_PREIMAGE_VALUE`, `RECOMPUTE_NOT_ATTEMPTED_MALFORMED_LIST` |
| `registered_set_completeness_status` | Is the registered set itself complete for every semantic dependency of the decision? | `REGISTERED_SET_COMPLETENESS_NOT_ESTABLISHABLE` (constant; **non-gating**) |

`required_verification_outcome` is `accept` only when the first three are `satisfied`; otherwise `reject`.
`registered_set_completeness_status` never gates it (it is `cannot_establish` on all 19 vectors).
`verification_status` is `satisfied` when the observed outcome equals the required one and `violated`
otherwise (an observed `accept` of a required `reject` is a fail-open).

### Epistemic status is separate from the operational result

An unregistered `policy_version` gives `preimage_schema_status = cannot_establish` and
`required_verification_outcome = reject`. "We have no authorized schema for this version" must not be
rewritten into the stronger factual claim "this schema is known to be unauthorized". Both cases reject;
they are not the same statement, and a relying party may treat them differently.

### One condition, two dimensions, two honest answers

A malformed declared list (`N4`-`N6`) is `violated` on `preimage_schema_status` but `cannot_establish` on
`decision_ref_recompute_status`, on purpose: the malformed declaration is the producer's fault (a violation
of the profile), while the verifier genuinely cannot recompute over something that is not a set of names.
A second implementer who maps both to the same status has made a silent mistake.

### A declaration is a field SET

Authority is over a set. Reordering a registered list preserves authorization. A list that repeats a
name is **malformed** (fail closed), not silently deduplicated, and a non-string entry is malformed, not
coerced or dropped. A recompute is never attempted against a malformed declaration, and it is never
attempted against a default list in its place.

## Registry

`vectors.json` carries a snapshot of the issuer's registry (19 policy versions), pinned by
`registry_sha256` (sha256 of its canonical JSON); the checker refuses a snapshot that does not match its
digest. Registry membership, not a one-version-one-schema assumption, is the authority: **one version can
register more than one historical state**. `invinoveritas.review.v18` registers two states that differ by
exactly one field (`external_evidence_hash`) because its field list changed mid-lifetime without a version
bump. Both are accepted only because the registry says so (`A3`, `A4`), which is the positive historical
control against a verifier that assumes one schema per version.

## Corpus (19 cases)

| case | what it isolates | schema | recompute | required |
|---|---|---|---|---|
| `A1_CONTROL_CURRENT_AUTHORIZED` | current version, full registered set | satisfied | satisfied | accept |
| `A2_REORDERED_DECLARED_LIST_SAME_SET` | reorder preserves authorization | satisfied | satisfied | accept |
| `A3_V18_REGISTERED_STATE_1` / `A4_V18_REGISTERED_STATE_2` | one version, two registered states | satisfied | satisfied | accept |
| `A5_CORE_NEGATIVE_CORRECTLY_REJECTED` | the core negative, judged by a correct verifier | violated | satisfied | reject |
| `N1_SELF_CONSISTENT_REDUCED_PREIMAGE` | **the core negative**: valid signature + self-consistent reduced preimage + recomputable `decision_ref`, observed accept | violated | satisfied | reject |
| `N2_SUPERSET_WITH_UNREGISTERED_FIELD` | an extra name is not a registered set | violated | satisfied | reject |
| `N3_UNREGISTERED_POLICY_VERSION` | `cannot_establish` (epistemic) vs `reject` (operational) | cannot_establish | satisfied | reject |
| `N4_DUPLICATE_NAME_MALFORMED` | repetition is malformed, not deduped | violated | cannot_establish | reject |
| `N5_NON_STRING_ENTRY_MALFORMED` | non-string is malformed, not coerced | violated | cannot_establish | reject |
| `N6_NON_LIST_DECLARATION_MALFORMED` | a non-list declaration | violated | cannot_establish | reject |
| `N7_RECOMPUTE_FAILURE_MUST_NOT_BYPASS_AUTHORIZATION` | recompute cannot be established on an unauthorized set | violated | cannot_establish | reject |
| `N8_DECISION_REF_TAMPERED` | authorized set, recompute fails | satisfied | violated | reject |
| `N9_SIGNATURE_INVALID_ISOLATED` | only the signature is bad; dimensions are independent | satisfied | satisfied | reject |
| `N10_CURRENT_SET_UNDER_OLD_VERSION` | authority is per the proof's OWN version | violated | satisfied | reject |
| `N11_DUPLICATE_CONTENT_MEMBER_MALFORMED` | the SIGNED content repeats a member name (last-wins and first-wins parsers read different verdicts) | cannot_establish | cannot_establish | reject |
| `N12_UNSUPPORTED_CANONICALIZATION_VERSION` | the proof names a serializer version this profile does not implement | satisfied | cannot_establish | reject |
| `N14_FLOAT_PREIMAGE_VALUE_OUT_OF_SCOPE` | a float (`0.5`) on an authorized set, `decision_ref` correct under RFC 8785: outside the profile's scope | satisfied | cannot_establish | reject |
| `N13_LONE_SURROGATE_PREIMAGE_VALUE` | a preimage value is a lone UTF-16 surrogate escape: valid JSON, no UTF-8 bytes | satisfied | cannot_establish | reject |

Every adversarial vector except `N9` has a valid signature under the test key, so each fixture isolates
schema authorization instead of conflating it with cryptographic validity. `N9` is the deliberate
exception that proves the signature dimension is independent of the other two.

## Mutation evidence

`mutation_check.py` applies one-site edits to `schema_check.py`. A mutant is **killed** only when the
dimension it targets changes on its witness case, judged against the full expected result, while the
controls (`A1` and `N8` by default) stay exactly as expected on every other dimension. Every status-level
dimension that changed is recorded (`changed_dimensions`, `also_changed`: the five status fields only, not
reason codes, `observed_verification_outcome` or `verification_status`), so a mutant that dies for a different
reason than intended is visible. 18 of 18 are killed.

This replaces an earlier criterion that judged every mutant on the scalar `required_verification_outcome`
alone. That collapsed the dimensions back into one verdict, the thing this profile exists to prevent:
a mutant that corrupted *which dimension reported what* survived whenever accept/reject happened to be
preserved (`M12` below, reported by an independent reviewer on #48).

| mutant | the bug | witness |
|---|---|---|
| `M1_DECLARED_SET_TRUSTED_DIRECTLY` | registry not consulted, the declared set is believed | `N1` |
| `M2_RECOMPUTE_FAILURE_BYPASSES_AUTHORIZATION` | when recompute cannot be established, the signature alone decides | `N7` |
| `M3_DUPLICATE_NAMES_SILENTLY_DEDUPED` | repeated names collapse | `N4` |
| `M4_NON_STRING_ENTRIES_COERCED_AWAY` | non-string entries dropped | `N5` |
| `M5_UNKNOWN_POLICY_VERSION_ACCEPTED` | no registry entry treated as authorized | `N3` |
| `M6_PROPER_SUBSET_ACCEPTED` | any subset of a registered set passes | `N1` |
| `M7_SUPERSET_ACCEPTED` | any superset of a registered set passes | `N2` |
| `M8_SIGNATURE_NOT_CHECKED` | signature dimension dropped | `N9` |
| `M9_LIST_ORDER_TREATED_AS_IDENTITY` | reordering breaks authorization | `A2` |
| `M10_ANY_VERSIONS_REGISTRY_ACCEPTED` | set authorized against any version's states | `N10` |
| `M11_ONE_VERSION_ONE_SCHEMA_ASSUMED` | only the first registered state per version accepted | `A4` |
| `M12_RECOMPUTE_OVER_REGISTERED_SET_NOT_DECLARED` | `decision_ref` recomputed over the registered set instead of the declared one; every authorized case unchanged and every unauthorized case rejected either way, so it **survived the scalar-outcome criterion**; it flips `decision_ref_recompute_status` on `N1`, `N2`, `N10`, `A5` | `N1` (dimension: recompute) |
| `M13_COMPLETENESS_CLAIMED_SATISFIED` | the constant completeness dimension reports `satisfied` | `A1` (dimension: completeness) |
| `M14_COMPLETENESS_NON_CLAIM_PROMOTED_TO_FAILURE` | `cannot_establish` completeness gates the outcome, rejecting authorized proofs | `A4` (dimension: outcome; controls are the two reject controls `N8`, `N9`, since the positive controls break by design) |
| `M15_DUPLICATE_MEMBERS_PARSED_LAST_WINS` | the signed content is parsed last-wins instead of failing closed on a repeated member name; the duplicate-member proof is then fully accepted | `N11` |
| `M16_CANONICALIZATION_VERSION_IGNORED` | the proof's `canonicalization_version` is never checked, so a proof naming another serializer is recomputed and accepted | `N12` |
| `M17_LONE_SURROGATE_TREATED_AS_SUPPORTED` | a lone-surrogate string is accepted as a supported preimage value; canonicalization then fails and the generic error path collapses every dimension (the visible change lands on `preimage_schema_status`, with `signature_status` also changed) | `N13` |
| `M18_FLOAT_ADMITTED_AS_SUPPORTED` | the checker admits float preimage values as supported; `json.dumps(0.5)` equals the RFC 8785 form so `N14` recomputes and reports satisfied/accept | `N14` |

**On `M2` (proposed observable definition).** "Authorize after recompute instead of before" is not
visible in an outcome when a verifier computes both and combines them. What is observable, and what this
profile pins, is that a recompute failure must not change who decides: on an unauthorized set with an
unsupported preimage value (`N7`), the outcome must still be `reject` by the schema dimension. If the
intended mutation is defined differently, `M2` is the one line to revise.

## Reference implementation and cross-check

The registry was extracted from the issuer's verifier
(`services/proof_signing.py`, `POLICY_VERSION_AUTHORIZED_PREIMAGE_FIELDS`, built by walking every commit
that ever touched the field list). The issuer's production verifier (`POST /verify-proof`) reports the
same split in `trust_basis`:

| this profile | `/verify-proof` `trust_basis` |
|---|---|
| `decision_ref_recompute_status` | `recomputed_by_verifier.decision_ref_hash_matches_declared_fields` (`null` = not established) |
| `preimage_schema_status` `satisfied` / `violated` / `cannot_establish` | `relayed_from_verifier_registry.preimage_schema_status` = `authorized` / `not_authorized_for_version` or `malformed_declared_list` / `cannot_establish` |
| `registered_set_completeness_status` | `relayed_from_verifier_registry.registered_set_completeness_status` (constant `cannot_establish`, non-gating) |
| `signature_status` | `checks.id_integrity` and `checks.signature_valid` |
| `required_verification_outcome` | `relayed_from_verifier_registry.required_verification_outcome` |

The two implementations share no code (this checker is standard-library only; the production verifier
uses the `rfc8785` library and its own signature path), but they share an author (see the limits above).

Compared **dimension by dimension**, not only on accept/reject (an outcome-only comparison hid the one
disagreement below): over all 19 events the production verifier and this checker agree on schema status,
signature status, recompute status, the completeness constant and the outcome, with **two named divergences** (`N7`, `N14`).
On `N7` the recompute dimension differs: production reports `violated` and this profile reports
`cannot_establish`. `N7` puts a float in the preimage. The profile refuses floats on purpose (its
standard-library canonicalizer cannot promise RFC 8785 identity for them); production canonicalizes them
through the `rfc8785` library, computes a real hash, and finds the (tampered) `decision_ref` does not
match. Both reject by the schema dimension, so the outcome agrees. The test pins this exact pair so any
change on either side fails it.


### Named scope divergences: `N7` (same outcome) and `N14` (different outcome)

The profile's answer is the narrower one **on purpose**: where production and this profile differ on a float, the profile's `cannot_establish` is the deliberate reading, not a gap to be closed by widening it.

On `N7` the profile and the issuer's production verifier agree on the **final outcome** (`reject`) and disagree
on the **epistemic basis**, deliberately:

| | recompute | `decision_ref_recompute_status` | schema authority | outcome |
|---|---|---|---|---|
| production (`/verify-proof`, real `rfc8785`) | established, mismatch found | `violated` | rejects | `reject` |
| this stdlib profile | outside the RFC 8785 domain it can guarantee (strings, `null`, safe integers) | `cannot_establish` | rejects | `reject` |

Same final outcome is not the same epistemic basis. The profile does not widen its canonicalization to force
parity of the intermediate status, and does not claim more of RFC 8785 than it implements; production is allowed
to be stronger because it has the real implementation. In both, the schema authority still rejects, so no
unauthorized proof is accepted through the gap. The parity test carries this as a named `KNOWN_DIVERGENCES`
entry rather than an unexplained skip. (Boundary framing from the review of `8894e13`.)

`N14` is the harder half and is stated plainly: a float on an **authorized** set whose `decision_ref` is correct.

| | recompute | `decision_ref_recompute_status` | schema authority | outcome |
|---|---|---|---|---|
| production (`/verify-proof`, real `rfc8785`) | established, matches | `satisfied` | authorized | `accept` (`combined_verification_outcome`) |
| this stdlib profile | outside its scope | `cannot_establish` | authorized | `reject` |

Here the **outcomes differ**, in the direction that matters: the profile is stricter. A consumer that needs this
profile's fail-closed guarantee should not treat production's `accept` on such an artifact as profile-conformant;
production is allowed to establish more than the profile because it carries the real implementation. Pinned as
`OUTCOME_DIVERGENCES` in the parity test.

**Production's outcome fields.** `relayed_from_verifier_registry.required_verification_outcome` keeps its
documented meaning (schema authority only, kept unchanged for existing consumers). The second field
`combined_verification_outcome` folds in every dimension (id integrity and signature, schema authorized, and the
recompute matching) and is what the parity test compares against this profile's outcome.

## Test key and regeneration

`trusted_pubkey` is derived from a fixed label (`test_key_label` in `vectors.json`) and authorizes
nothing. Signatures are BIP-340 with all-zero auxiliary randomness, so regeneration is byte-identical:

```sh
python3 generate_vectors.py   # rewrites vectors.json from the pinned registry it already carries
```

## Additional checks

```sh
python3 -O schema_check.py vectors.json | cmp - <(python3 schema_check.py vectors.json)   # no assert-dependent logic
```

The signature check is validated against the official BIP-340 test vectors (indices 0 and 4 valid,
index 5 invalid) at authoring time.
