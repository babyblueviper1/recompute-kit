#!/usr/bin/env python3
"""Deterministically (re)generate vectors.json for authorized_preimage_schema.v0.

    python3 generate_vectors.py --registry registry_extract.json   # first time: registry from the issuer
    python3 generate_vectors.py                                    # later: reuse the pinned registry in vectors.json

The signing key is a PUBLISHED TEST KEY derived from a fixed label. It authorizes nothing anywhere.
Signatures are BIP-340 with all-zero auxiliary randomness, so regeneration is byte-identical.
"""

import hashlib
import json
from pathlib import Path
import sys

import schema_check as sc

HERE = Path(__file__).resolve().parent
KEY_LABEL = b"recompute-kit/authorized-preimage-schema-v0/test-key/not-a-real-key"
SECKEY = int.from_bytes(hashlib.sha256(KEY_LABEL).digest(), "big") % sc.ORDER
# A second, deterministic, equally-published TEST key -- authorizes nothing anywhere, same as SECKEY. Used ONLY to
# construct N18 (an event genuinely self-signed by a REAL key that simply isn't the one this suite's registry
# trusts), so issuer_status has its own honest positive AND negative case, not just the positive.
UNTRUSTED_KEY_LABEL = b"recompute-kit/authorized-preimage-schema-v0/test-key/untrusted-not-a-real-key"
UNTRUSTED_SECKEY = int.from_bytes(hashlib.sha256(UNTRUSTED_KEY_LABEL).digest(), "big") % sc.ORDER
CREATED_AT = 1789900000
NULL_FIELDS = {"related_decision_ref", "registry_as_of", "registry_snapshot_sha256", "epistemic_basis",
               "external_evidence_hash", "vantage_limitation", "intended_audience", "intended_verifier"}


def schnorr_sign(message, seckey):
    point = sc.point_mul(sc.BASE, seckey)
    d = seckey if point[1] % 2 == 0 else sc.ORDER - seckey
    t = (d ^ int.from_bytes(sc.tagged_hash("BIP0340/aux", bytes(32)), "big")).to_bytes(32, "big")
    x = point[0].to_bytes(32, "big")
    k0 = int.from_bytes(sc.tagged_hash("BIP0340/nonce", t + x + message), "big") % sc.ORDER
    r_point = sc.point_mul(sc.BASE, k0)
    k = k0 if r_point[1] % 2 == 0 else sc.ORDER - k0
    r = r_point[0].to_bytes(32, "big")
    e = int.from_bytes(sc.tagged_hash("BIP0340/challenge", r + x + message), "big") % sc.ORDER
    return r + ((k + e * d) % sc.ORDER).to_bytes(32, "big")


PUBKEY = sc.point_mul(sc.BASE, SECKEY)[0].to_bytes(32, "big").hex()
UNTRUSTED_PUBKEY = sc.point_mul(sc.BASE, UNTRUSTED_SECKEY)[0].to_bytes(32, "big").hex()


def field_value(name, version):
    if name == "policy_version":
        return version
    if name == "verdict":
        return "approve"
    if name == "artifact_type":
        return "code_diff"
    if name == "canonicalization_version":
        return "rfc8785.v1"
    if name in NULL_FIELDS:
        return None
    return "example:" + name


def make_event(case_id, index, version, declared, hashed_names, universe, overrides=None, tamper=None, raw_edit=None, ascii_body=False, kind=30078, utf16_keys=False, untrusted_key=False):
    """A signed NIP-01 event whose content carries every field in `universe`, the declared list as given,
    and a decision_ref computed over `hashed_names` (what an honest producer of THAT declaration hashed).
    untrusted_key=True signs with UNTRUSTED_SECKEY/UNTRUSTED_PUBKEY instead of the suite's trusted key --
    a genuinely self-consistent event (its own id/sig check out against its own embedded pubkey), just not
    signed by the key this suite's registry trusts. Used only for N18 (issuer_status's own negative case)."""
    pubkey, seckey = (UNTRUSTED_PUBKEY, UNTRUSTED_SECKEY) if untrusted_key else (PUBKEY, SECKEY)
    content = {name: field_value(name, version) for name in universe}
    content["schema"] = "invinoveritas.verdict_proof.v1"   # not in any preimage; lets the issuer's is_proof_event (kind + schema prefix) hold on the fixture
    content.update(overrides or {})
    content["policy_version"] = version
    content["decision_ref_preimage_fields"] = declared
    if hashed_names is not None:
        preimage = {name: content.get(name) for name in hashed_names}
        if utf16_keys:   # RFC 8785 order: property names by UTF-16 code unit (differs from the stdlib code-point order)
            canon = json.dumps({k: preimage[k] for k in sorted(preimage, key=lambda n: n.encode("utf-16-be"))},
                               separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        else:
            canon = sc.canonical(preimage)
        content["decision_ref"] = "sha256:" + hashlib.sha256(canon).hexdigest()
    if tamper == "decision_ref":
        content["decision_ref"] = "sha256:" + hashlib.sha256(b"a different preimage").hexdigest()
    if tamper == "unhashable":
        content["decision_ref"] = "sha256:" + "00" * 32
    body = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=bool(ascii_body))
    if raw_edit is not None:
        body = raw_edit(body)   # edits the SIGNED content text itself (e.g. to repeat a member name)
    tags = [["d", "authorized-preimage-schema-v0/" + case_id]]
    created = CREATED_AT + index
    serialized = json.dumps([0, pubkey, created, kind, tags, body], separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(serialized.encode("utf-8")).digest()
    signature = schnorr_sign(digest, seckey).hex()
    if tamper == "signature":
        signature = signature[:-1] + ("0" if signature[-1] != "0" else "1")
    return {"id": digest.hex(), "pubkey": pubkey, "created_at": created, "kind": kind, "tags": tags,
            "content": body, "sig": signature}


# Expected results are AUTHORED HERE, from each case's stated purpose and the profile's prose rules, and are NOT
# produced by running the checker under test. (An earlier revision set entry["expected"] = sc.evaluate(...), which
# made "N/N reproduced" mean only "the checker is deterministic", not "the expected values are right"; a reviewer
# rightly flagged that.) The generator now fails loudly if schema_check.py disagrees with this table. It is still
# the same author's reading of the rules, so this establishes reproduction of an authored expectation, not
# independence -- see the README's Evidence section for what the cross-check against /verify-proof adds.
SIG_OK = ("satisfied", "SIGNATURE_VALID")
ISSUER_OK = ("satisfied", "ISSUER_TRUSTED")
PROOF_EVENT_OK = ("satisfied", "PROOF_EVENT_KIND")
SCHEMA_OK = ("satisfied", "DECLARED_SET_REGISTERED")
SCHEMA_NOT_REG = ("violated", "DECLARED_SET_NOT_REGISTERED_FOR_VERSION")
SCHEMA_MALFORMED = ("violated", "MALFORMED_DECLARED_LIST")
REC_OK = ("satisfied", "DECISION_REF_RECOMPUTED")
REC_NOT_ATTEMPTED = ("cannot_establish", "RECOMPUTE_NOT_ATTEMPTED_MALFORMED_LIST")


def authored(sig, issuer, proof_event, schema, rec, required, observed):
    return {"signature_status": sig[0], "issuer_status": issuer[0], "proof_event_status": proof_event[0],
            "preimage_schema_status": schema[0],
            "decision_ref_recompute_status": rec[0],
            "registered_set_completeness_status": "cannot_establish",
            "required_verification_outcome": required, "observed_verification_outcome": observed,
            "verification_status": "satisfied" if observed == required else "violated",
            "reason_codes": sorted([sig[1], issuer[1], proof_event[1], schema[1], rec[1],
                                    "REGISTERED_SET_COMPLETENESS_NOT_ESTABLISHABLE"])}


EXPECTED = {
    "A1_CONTROL_CURRENT_AUTHORIZED": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, REC_OK, "accept", "accept"),
    "A2_REORDERED_DECLARED_LIST_SAME_SET": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, REC_OK, "accept", "accept"),
    "A3_V18_REGISTERED_STATE_1": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, REC_OK, "accept", "accept"),
    "A4_V18_REGISTERED_STATE_2": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, REC_OK, "accept", "accept"),
    "A5_CORE_NEGATIVE_CORRECTLY_REJECTED": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_NOT_REG, REC_OK, "reject", "reject"),
    "N1_SELF_CONSISTENT_REDUCED_PREIMAGE": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_NOT_REG, REC_OK, "reject", "accept"),
    "N2_SUPERSET_WITH_UNREGISTERED_FIELD": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_NOT_REG, REC_OK, "reject", "accept"),
    "N3_UNREGISTERED_POLICY_VERSION": authored(
        SIG_OK, ISSUER_OK, PROOF_EVENT_OK, ("cannot_establish", "POLICY_VERSION_NOT_REGISTERED"), REC_OK, "reject", "accept"),
    "N4_DUPLICATE_NAME_MALFORMED": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_MALFORMED, REC_NOT_ATTEMPTED, "reject", "accept"),
    "N5_NON_STRING_ENTRY_MALFORMED": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_MALFORMED, REC_NOT_ATTEMPTED, "reject", "accept"),
    "N6_NON_LIST_DECLARATION_MALFORMED": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_MALFORMED, REC_NOT_ATTEMPTED, "reject", "accept"),
    "N7_RECOMPUTE_FAILURE_MUST_NOT_BYPASS_AUTHORIZATION": authored(
        SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_NOT_REG, ("cannot_establish", "UNSUPPORTED_PREIMAGE_VALUE"), "reject", "accept"),
    "N8_DECISION_REF_TAMPERED": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, ("violated", "DECISION_REF_MISMATCH"), "reject", "accept"),
    "N9_SIGNATURE_INVALID_ISOLATED": authored(("violated", "SIGNATURE_INVALID"), ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, REC_OK, "reject", "accept"),
    "N10_CURRENT_SET_UNDER_OLD_VERSION": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_NOT_REG, REC_OK, "reject", "accept"),
    # Reported by an independent reviewer on #48 (2026-09-21):
    "N11_DUPLICATE_CONTENT_MEMBER_MALFORMED": dict(
        authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, ("cannot_establish", "MALFORMED_CONTENT"), ("cannot_establish", "MALFORMED_CONTENT"), "reject", "accept"),
        reason_codes=sorted(["SIGNATURE_VALID", "ISSUER_TRUSTED", "PROOF_EVENT_KIND", "MALFORMED_CONTENT", "REGISTERED_SET_COMPLETENESS_NOT_ESTABLISHABLE"])),
    "N12_UNSUPPORTED_CANONICALIZATION_VERSION": authored(
        SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, ("cannot_establish", "UNSUPPORTED_CANONICALIZATION_VERSION"), "reject", "accept"),
    "N13_LONE_SURROGATE_PREIMAGE_VALUE": authored(
        SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, ("cannot_establish", "UNSUPPORTED_PREIMAGE_VALUE"), "reject", "accept"),
    # Reported on #48 (2026-09-21): scope of the profile's canonicalizer is normative, not an implementation note.
    "N14_FLOAT_PREIMAGE_VALUE_OUT_OF_SCOPE": authored(
        SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_OK, ("cannot_establish", "UNSUPPORTED_PREIMAGE_VALUE"), "reject", "accept"),
    # Reported by pipavlo82 on #48 (2026-09-21, tree-level pass): valid signature, trusted issuer, wrong kind --
    # a fact about the event's TYPE, not its signature. Split 2026-09-22 (pipavlo82 + MattyIceMatrix): now its own
    # proof_event_status dimension instead of folded into signature_status.
    "N15_AUTHENTIC_EVENT_UNDER_WRONG_KIND": authored(
        SIG_OK, ISSUER_OK, ("violated", "EVENT_KIND_NOT_AUTHORIZED"), SCHEMA_OK, REC_OK, "reject", "accept"),
    "N16_NON_ASCII_DECLARED_NAMES": authored(SIG_OK, ISSUER_OK, PROOF_EVENT_OK, SCHEMA_MALFORMED, REC_NOT_ATTEMPTED, "reject", "accept"),
    "N17_INVALID_CASE_MUST_KEEP_OBSERVED_OUTCOME": {
        "signature_status": "cannot_establish", "issuer_status": "cannot_establish", "proof_event_status": "cannot_establish",
        "preimage_schema_status": "cannot_establish",
        "decision_ref_recompute_status": "cannot_establish", "registered_set_completeness_status": "cannot_establish",
        "required_verification_outcome": "reject", "observed_verification_outcome": "accept", "verification_status": "violated",
        "reason_codes": sorted(["INVALID_CASE", "REGISTERED_SET_COMPLETENESS_NOT_ESTABLISHABLE"])},
    # 2026-09-22 (MattyIceMatrix on #48): valid signature, valid event id, correct kind, authorized/recomputable
    # preimage -- but signed by a key that is simply not the pinned one. Real signed content by a real key, just
    # not the trusted one: issuer_status is its own honest "violated", independent of signature_status (which is
    # satisfied -- the signature over THIS event, by ITS OWN pubkey, genuinely checks out).
    "N18_AUTHENTIC_EVENT_UNDER_UNTRUSTED_KEY": authored(
        SIG_OK, ("violated", "UNTRUSTED_PUBKEY"), PROOF_EVENT_OK, SCHEMA_OK, REC_OK, "reject", "accept"),
}


def main():
    path = HERE / "vectors.json"
    if "--registry" in sys.argv:
        extract = json.loads(Path(sys.argv[sys.argv.index("--registry") + 1]).read_text(encoding="utf-8"))
        registry, current = extract["registry"], extract["current"]
    else:
        old = json.loads(path.read_text(encoding="utf-8"))
        registry, current = old["registry"], old["current_policy_version"]
    current_set = sorted(registry["states"][current][0])
    v18_a, v18_b = registry["states"]["invinoveritas.review.v18"]
    universe = sorted(set(current_set) | set(v18_a) | set(v18_b) | {"x_unregistered_field"})
    reduced = [n for n in current_set if n != "action_binding_args_hash"]
    ids = iter(range(1000))

    def case(case_id, purpose, version, declared, hashed, observed, overrides=None, tamper=None, raw_edit=None, ascii_body=False,
             kind=30078, utf16_keys=False, extra_inputs=None, untrusted_key=False):
        event = make_event(case_id, next(ids), version, declared, hashed, universe, overrides, tamper, raw_edit, ascii_body, kind, utf16_keys, untrusted_key)
        entry = {"case_id": case_id, "purpose": purpose,
                 "inputs": {"event": event, "observed_verification_outcome": observed, **(extra_inputs or {})}}
        entry["expected"] = EXPECTED[case_id]
        actual = sc.evaluate(entry, registry, PUBKEY)
        if actual != entry["expected"]:
            diff = {k: (entry["expected"][k], actual[k]) for k in entry["expected"] if actual.get(k) != entry["expected"][k]}
            raise SystemExit("authored expectation disagrees with schema_check.py for %s: %s" % (case_id, diff))
        return entry

    cases = [
        case("A1_CONTROL_CURRENT_AUTHORIZED", "Current version, full registered set, valid signature: accept.",
             current, current_set, current_set, "accept"),
        case("A2_REORDERED_DECLARED_LIST_SAME_SET", "Reordering a registered set preserves authorization.",
             current, list(reversed(current_set)), current_set, "accept"),
        case("A3_V18_REGISTERED_STATE_1", "Historical control: one policy version, first of two registered states.",
             "invinoveritas.review.v18", sorted(v18_a), v18_a, "accept"),
        case("A4_V18_REGISTERED_STATE_2", "Historical control: the second registered state of the same version; "
             "accepted only because the registry authorizes it (no one-version-one-schema assumption).",
             "invinoveritas.review.v18", sorted(v18_b), v18_b, "accept"),
        case("A5_CORE_NEGATIVE_CORRECTLY_REJECTED", "The core negative, judged by a verifier that rejects it: satisfied.",
             current, reduced, reduced, "reject"),
        case("N1_SELF_CONSISTENT_REDUCED_PREIMAGE", "Valid signature + self-consistent reduced preimage + "
             "recomputable decision_ref != authorized preimage schema. Observed accept is a fail-open.",
             current, reduced, reduced, "accept"),
        case("N2_SUPERSET_WITH_UNREGISTERED_FIELD", "Authorized set plus one unregistered name is not a registered set.",
             current, current_set + ["x_unregistered_field"], current_set + ["x_unregistered_field"], "accept"),
        case("N3_UNREGISTERED_POLICY_VERSION", "No registry entry for the version: preimage_schema_status is "
             "cannot_establish (epistemic) while the required outcome is reject (operational).",
             "vendor.review.v999", current_set, current_set, "accept"),
        case("N4_DUPLICATE_NAME_MALFORMED", "A repeated name is malformed, not silently deduped.",
             current, current_set + [current_set[0]], current_set, "accept"),
        case("N5_NON_STRING_ENTRY_MALFORMED", "A non-string entry is malformed, not coerced or dropped.",
             current, current_set + [7], current_set, "accept"),
        case("N6_NON_LIST_DECLARATION_MALFORMED", "A declaration that is not a list is malformed.",
             current, {"verdict": True}, current_set, "accept"),
        case("N7_RECOMPUTE_FAILURE_MUST_NOT_BYPASS_AUTHORIZATION", "Recompute cannot be established (unsupported "
             "preimage value) on an unauthorized set: authorization must still gate the outcome.",
             current, reduced, None, "accept", overrides={"artifact_type": 0.5}, tamper="unhashable"),
        case("N8_DECISION_REF_TAMPERED", "Authorized set, valid signature, decision_ref does not recompute.",
             current, current_set, current_set, "accept", tamper="decision_ref"),
        case("N9_SIGNATURE_INVALID_ISOLATED", "Everything else authorized and recomputable; only the signature "
             "is invalid. Shows the dimensions are independent.",
             current, current_set, current_set, "accept", tamper="signature"),
        case("N10_CURRENT_SET_UNDER_OLD_VERSION", "The current field set declared under v1: authority is per the "
             "proof's OWN policy_version, not any version.",
             "invinoveritas.review.v1", current_set, current_set, "accept"),
        case("N11_DUPLICATE_CONTENT_MEMBER_MALFORMED", "The SIGNED content repeats a member name (verdict). A last-wins "
             "parser reads 'approve', a first-wins parser reads 'reject': malformed, not silently resolved.",
             current, current_set, current_set, "accept", raw_edit=lambda b: '{"verdict":"reject",' + b[1:]),
        case("N12_UNSUPPORTED_CANONICALIZATION_VERSION", "The proof names a serializer version this profile does not "
             "implement: recompute cannot be established (not violated, not satisfied), so the outcome is reject.",
             current, current_set, current_set, "accept", overrides={"canonicalization_version": "rfc8785.v2"}),
        case("N13_LONE_SURROGATE_PREIMAGE_VALUE", "A preimage value is a lone UTF-16 surrogate escape: valid JSON, no "
             "UTF-8 bytes, so it cannot be canonicalized. recompute is cannot_establish with the other dimensions "
             "intact, not a crash and not a generic INVALID_CASE.",
             current, current_set, None, "accept", overrides={"artifact_type": "\ud800"}, tamper="unhashable", ascii_body=True),
        case("N14_FLOAT_PREIMAGE_VALUE_OUT_OF_SCOPE", "A preimage value is a float (0.5) on an AUTHORIZED set and the "
             "decision_ref is correct under RFC 8785. The profile's scope is string, null and safe integer: a float is "
             "outside it, so recompute is cannot_establish and the outcome is reject, even though a library that "
             "implements ECMAScript Number::toString would establish it. Fail-closed by scope, not by disagreement.",
             current, current_set, current_set, "accept", overrides={"artifact_type": 0.5}),
        case("N15_AUTHENTIC_EVENT_UNDER_WRONG_KIND", "The authorized set, a correct decision_ref and a VALID signature, but the event is "
             "kind 1, not the proof-event kind 30078: authentic signed content is not an authorized proof-event type.",
             current, current_set, current_set, "accept", kind=1),
        case("N16_NON_ASCII_DECLARED_NAMES", "Declared preimage names U+E000 and U+10000 sort differently by code point (stdlib) and by "
             "UTF-16 code unit (RFC 8785). The decision_ref is correct under RFC 8785; the profile requires ASCII names, so the declaration "
             "is malformed and the recompute is not attempted rather than computed in a possibly-wrong order.",
             current, current_set + ["\ue000", "\U00010000"], current_set + ["\ue000", "\U00010000"], "accept",
             overrides={"\ue000": "example:private-use", "\U00010000": "example:linear-b"}, utf16_keys=True),
        case("N17_INVALID_CASE_MUST_KEEP_OBSERVED_OUTCOME", "The harness input is malformed (an unexpected extra key), so the verifier cannot "
             "evaluate it. What the implementation under test actually did (accept) must be preserved, not rewritten to reject.",
             current, current_set, current_set, "accept", extra_inputs={"unexpected_key": "makes this an invalid case"}),
        case("N18_AUTHENTIC_EVENT_UNDER_UNTRUSTED_KEY", "The authorized set, a correct decision_ref, the right kind, and a genuinely "
             "VALID signature -- but over the event's OWN (real, self-consistent) key, which is simply not the one this registry trusts. "
             "signature_status is satisfied (the signature over this event by its own pubkey checks out); issuer_status alone is violated.",
             current, current_set, current_set, "accept", untrusted_key=True),
    ]
    document = {"profile": sc.PROFILE, "trusted_pubkey": PUBKEY, "test_key_label": KEY_LABEL.decode(),
                "current_policy_version": current, "registry": registry,
                "registry_sha256": sc.registry_digest(registry), "cases": cases}
    path.write_text(json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(cases), "registry_sha256": document["registry_sha256"], "pubkey": PUBKEY}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
