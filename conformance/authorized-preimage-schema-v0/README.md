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
must report the three dimensions separately instead of one scalar "verified".

Status: `authorized_preimage_schema.v0`, vectors + checker + mutation evidence. Shaped like
`consumption-time-state-binding-v0` (#46).

## What this profile does not establish

*(Written first, before the checker and vectors: these are the claims this profile is not allowed to make.)*

A reference set is its maintainer's claim about which fields a decision commits to. A verifier can
recompute against it and can report who holds the authority, but it cannot establish that the set is
complete or correct, and nothing inside the producer's boundary can.

- **Completeness and correctness of the registry are not established.** The snapshot is a producer-side
  claim. `registry_sha256` pins its content, not its truthfulness.
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
- **Canonicalization scope.** Preimage values are strings, `null`, or safe integers, where RFC 8785
  output equals compact sorted-key JSON. Any other value type makes the recompute `cannot_establish`
  (`N7`), deliberately, rather than guessing a serialization.
- **Coverage is finite.** 15 cases and 11 one-site mutations show these bugs are caught, not that no
  other bug exists.

## Recompute it (no dependencies beyond Python 3)

```sh
python3 schema_check.py vectors.json   # 15/15 reproduced; exit 0
python3 mutation_check.py              # 11/11 KILLED, controls preserved; exit 0
```

## What a case supplies

- a signed NIP-01 event (kind 30078) whose `content` is a JSON object carrying `decision_ref`,
  `decision_ref_preimage_fields` (the declared list), `policy_version`, and the values of the fields;
- a pinned registry snapshot (`registry`, with `registry_sha256`) mapping each policy version to its
  registered field-set states, and a `trusted_pubkey` (a published test key, see below);
- `observed_verification_outcome`: what the verifier under test returned (`accept` / `reject`).

The checker computes the **required** outcome independently and never reads the observed one.

## Three dimensions, established separately

Each dimension is tri-state (`satisfied` / `violated` / `cannot_establish`). `cannot_establish` is its
own answer and is never rewritten into `violated`.

| dimension | question | reason codes |
|---|---|---|
| `signature_status` | Does the BIP-340 signature verify over the NIP-01 event id, under the trusted key? | `SIGNATURE_VALID`, `SIGNATURE_INVALID`, `EVENT_ID_MISMATCH`, `UNTRUSTED_PUBKEY`, `MALFORMED_EVENT` |
| `preimage_schema_status` | Is the declared field **set** registered for the proof's own `policy_version`? | `DECLARED_SET_REGISTERED`, `DECLARED_SET_NOT_REGISTERED_FOR_VERSION`, `POLICY_VERSION_NOT_REGISTERED`, `MALFORMED_DECLARED_LIST` |
| `decision_ref_recompute_status` | Does `decision_ref` equal `sha256(JCS({name: content[name]}))` over **exactly the declared names** (absent -> `null`)? | `DECISION_REF_RECOMPUTED`, `DECISION_REF_MISMATCH`, `UNSUPPORTED_PREIMAGE_VALUE`, `RECOMPUTE_NOT_ATTEMPTED_MALFORMED_LIST` |

`required_verification_outcome` is `accept` only when all three are `satisfied`; otherwise `reject`.
`verification_status` is `satisfied` when the observed outcome equals the required one and `violated`
otherwise (an observed `accept` of a required `reject` is a fail-open).

### Epistemic status is separate from the operational result

An unregistered `policy_version` gives `preimage_schema_status = cannot_establish` and
`required_verification_outcome = reject`. "We have no authorized schema for this version" must not be
rewritten into the stronger factual claim "this schema is known to be unauthorized". Both cases reject;
they are not the same statement, and a relying party may treat them differently.

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

## Corpus (15 cases)

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

Every adversarial vector except `N9` has a valid signature under the test key, so each fixture isolates
schema authorization instead of conflating it with cryptographic validity. `N9` is the deliberate
exception that proves the signature dimension is independent of the other two.

## Mutation evidence

`mutation_check.py` applies one-site edits to `schema_check.py`. Each named verifier bug must flip
`required_verification_outcome` on its witness case while the positive control (`A1`) and a negative
control (`N8`) stay exactly as expected. 11 of 11 are killed.

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
| `required_verification_outcome` | `relayed_from_verifier_registry.required_verification_outcome` |

The two implementations share no code (this checker is standard-library only; the production verifier
uses the `rfc8785` library and its own signature path), but they share an author (see the limits above). Running the production verifier over all 15
events gave the same schema status and the same accept/reject outcome on 15 of 15.

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
