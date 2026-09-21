#!/usr/bin/env python3
"""Authorized preimage schema: a self-consistent decision_ref is not an authorized one.

Standard library only. Three independent gating dimensions (plus a constant, non-gating fourth) are established
separately and only then combined: signature (BIP-340 over the NIP-01 event id), preimage-schema authority (the declared
field list against a pinned registry, as a SET), and recompute (decision_ref over exactly the
declared names). "cannot_establish" is its own answer and is never rewritten into "violated".
"""

import hashlib
import json
from pathlib import Path
import sys

PROFILE = "authorized_preimage_schema.v0"
MAX_SAFE_INT = 2 ** 53

# ---- secp256k1 / BIP-340 (verification only; signing lives in generate_vectors.py) -------------
FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = (3 * a[0] * a[0] * pow(2 * a[1], FIELD - 2, FIELD)) % FIELD
    else:
        lam = ((b[1] - a[1]) * pow(b[0] - a[0], FIELD - 2, FIELD)) % FIELD
    x = (lam * lam - a[0] - b[0]) % FIELD
    return (x, (lam * (a[0] - x) - a[1]) % FIELD)


def point_mul(point, k):
    result = None
    for i in range(256):
        if (k >> i) & 1:
            result = point_add(result, point)
        point = point_add(point, point)
    return result


def tagged_hash(tag, message):
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest + message).digest()


def lift_x(x):
    if x >= FIELD:
        return None
    y_sq = (pow(x, 3, FIELD) + 7) % FIELD
    y = pow(y_sq, (FIELD + 1) // 4, FIELD)
    if pow(y, 2, FIELD) != y_sq:
        return None
    return (x, y if y % 2 == 0 else FIELD - y)


def schnorr_verify(message, pubkey, signature):
    if len(message) != 32 or len(pubkey) != 32 or len(signature) != 64:
        return False
    point = lift_x(int.from_bytes(pubkey, "big"))
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if point is None or r >= FIELD or s >= ORDER:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + pubkey + message), "big") % ORDER
    candidate = point_add(point_mul(BASE, s), point_mul(point, ORDER - e))
    return candidate is not None and candidate[1] % 2 == 0 and candidate[0] == r


# ---- canonical bytes ---------------------------------------------------------------------------
def _encodable(text):
    """A str that has UTF-8 bytes. json.loads accepts a lone surrogate escape (\\ud800), which cannot be encoded."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def supported(value):
    """Preimage values this profile can canonicalize identically to RFC 8785: string, null, safe int."""
    if value is None:
        return True
    if type(value) is str:
        return _encodable(value)  # M17
    return type(value) is int and -MAX_SAFE_INT < value < MAX_SAFE_INT


SUPPORTED_CANONICALIZATION = "rfc8785.v1"   # the serializer this profile's canonical() implements


def no_duplicate_members(pairs):
    """object_pairs_hook: a JSON object with a repeated member name is malformed, not last-wins. Two parsers can
    read different values from the same signed bytes (RFC 7493 s2.3 forbids it)."""
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate member name %r" % key)
        out[key] = value
    return out


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def registry_digest(registry):
    return hashlib.sha256(canonical(registry)).hexdigest()


# ---- the three dimensions ----------------------------------------------------------------------
def signature_status(event, trusted_pubkey):
    try:
        if not (isinstance(event, dict) and type(event["created_at"]) is int and type(event["kind"]) is int
                and isinstance(event["tags"], list) and isinstance(event["content"], str)):
            return "cannot_establish", "MALFORMED_EVENT"
        if event["pubkey"] != trusted_pubkey:
            return "violated", "UNTRUSTED_PUBKEY"
        serialized = json.dumps([0, event["pubkey"], event["created_at"], event["kind"], event["tags"],
                                 event["content"]], separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(serialized.encode("utf-8")).digest()
        if digest.hex() != event["id"]:
            return "violated", "EVENT_ID_MISMATCH"
        if not schnorr_verify(digest, bytes.fromhex(event["pubkey"]), bytes.fromhex(event["sig"])):
            return "violated", "SIGNATURE_INVALID"
        return "satisfied", "SIGNATURE_VALID"
    except (KeyError, TypeError, ValueError):
        return "cannot_establish", "MALFORMED_EVENT"


def declared_names(declared):
    """The declared field list as a tuple of names, or None when it is not a well-formed declaration of a
    field SET: a list of plain strings with no repeated name. Reordering is fine; repetition is malformed.
    None maps to "violated" on schema_status but "cannot_establish" on recompute_status ON PURPOSE: a malformed
    declaration is the producer's fault (a violation of the profile), while the verifier genuinely cannot recompute
    over a list that is not a set of names. Same input condition, different dimension, different honest answer."""
    if not (isinstance(declared, list) and all(type(f) is str for f in declared)):  # M4
        return None
    if len(set(declared)) != len(declared):  # M3
        return None
    return tuple(declared)


def schema_status(declared, policy_version, registry):
    """Authority over the declared field SET for the proof's OWN policy_version."""
    names = declared_names(declared)
    if names is None:
        return "violated", "MALFORMED_DECLARED_LIST"
    states = registry["states"].get(policy_version) if isinstance(policy_version, str) else None
    if states is None:  # M5
        return "cannot_establish", "POLICY_VERSION_NOT_REGISTERED"
    if any(set(names) == set(state) for state in states):  # M1/M6/M7/M9/M10/M11
        return "satisfied", "DECLARED_SET_REGISTERED"
    return "violated", "DECLARED_SET_NOT_REGISTERED_FOR_VERSION"


def recompute_status(content, declared):
    """decision_ref over exactly the declared names (absent -> null), never over a default list."""
    names = declared_names(declared)
    if names is None:
        return "cannot_establish", "RECOMPUTE_NOT_ATTEMPTED_MALFORMED_LIST"
    if "canonicalization_version" in names and content.get("canonicalization_version") != SUPPORTED_CANONICALIZATION:  # M16
        return "cannot_establish", "UNSUPPORTED_CANONICALIZATION_VERSION"
    preimage = {name: content.get(name) for name in names}
    if not all(_encodable(name) and supported(v) for name, v in preimage.items()):
        return "cannot_establish", "UNSUPPORTED_PREIMAGE_VALUE"
    if "sha256:" + hashlib.sha256(canonical(preimage)).hexdigest() != content.get("decision_ref"):
        return "violated", "DECISION_REF_MISMATCH"
    return "satisfied", "DECISION_REF_RECOMPUTED"


def required_outcome(signature, schema, recompute):
    if signature == "satisfied" and schema == "satisfied" and recompute == "satisfied":  # M2/M8
        return "accept"
    return "reject"


# Completeness of the REGISTRY's authorized set for every semantic dependency of the decision is not something this
# profile can establish: it can show the declared set is registered for the proof's own policy_version and that
# decision_ref recomputes over exactly that set, not that the registered set itself is semantically complete.
# So it is reported as its own dimension, always "cannot_establish", and is deliberately NON-GATING: an "accept"
# means only "this proof conforms to the registered preimage schema", never "the registered schema is complete".
COMPLETENESS_STATUS = "cannot_establish"
COMPLETENESS_REASON = "REGISTERED_SET_COMPLETENESS_NOT_ESTABLISHABLE"


def result(signature, schema, recompute, required, observed, reasons):
    return {"signature_status": signature, "preimage_schema_status": schema,
            "decision_ref_recompute_status": recompute,
            "registered_set_completeness_status": COMPLETENESS_STATUS,
            "required_verification_outcome": required,
            "observed_verification_outcome": observed,
            "verification_status": "satisfied" if observed == required else "violated",
            "reason_codes": sorted(list(reasons) + [COMPLETENESS_REASON])}


def evaluate(case, registry, trusted_pubkey):
    try:
        return _evaluate(case["inputs"], registry, trusted_pubkey)
    except (ValueError, KeyError, TypeError):
        return result("cannot_establish", "cannot_establish", "cannot_establish", "reject", "reject",
                      ["INVALID_CASE"])


def _evaluate(data, registry, trusted_pubkey):
    if not (isinstance(data, dict) and set(data) == {"event", "observed_verification_outcome"}
            and data["observed_verification_outcome"] in {"accept", "reject"}):
        raise ValueError("invalid case")
    signature, sig_reason = signature_status(data["event"], trusted_pubkey)
    try:
        content = json.loads(data["event"]["content"], object_pairs_hook=no_duplicate_members)  # M15
        if not isinstance(content, dict):
            raise ValueError("content is not an object")
    except (ValueError, KeyError, TypeError):
        return result(signature, "cannot_establish", "cannot_establish", "reject",
                      data["observed_verification_outcome"], [sig_reason, "MALFORMED_CONTENT"])
    declared = content.get("decision_ref_preimage_fields")
    schema, schema_reason = schema_status(declared, content.get("policy_version"), registry)
    recompute, recompute_reason = recompute_status(content, declared)
    required = required_outcome(signature, schema, recompute)
    return result(signature, schema, recompute, required, data["observed_verification_outcome"],
                  [sig_reason, schema_reason, recompute_reason])


def load_document(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_members)
    if not (document["profile"] == PROFILE and bool(document["cases"])):
        raise ValueError("invalid document")
    if registry_digest(document["registry"]) != document["registry_sha256"]:
        raise ValueError("registry snapshot does not match its pinned digest")
    ids = [c["case_id"] for c in document["cases"]]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate case_id")
    return document


def main():
    document = load_document(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("vectors.json"))
    registry, pubkey = document["registry"], document["trusted_pubkey"]
    results = []
    for case in document["cases"]:
        actual = evaluate(case, registry, pubkey)
        results.append({"case_id": case["case_id"], "result": actual, "reproduced": actual == case["expected"]})
    counts = {axis: {s: sum(r["result"][axis] == s for r in results)
                     for s in ("satisfied", "violated", "cannot_establish")}
              for axis in ("signature_status", "preimage_schema_status", "decision_ref_recompute_status",
                   "registered_set_completeness_status")}
    print(json.dumps({"results": results, "counts": counts, "total": len(results),
                      "reproduced": sum(r["reproduced"] for r in results)}, sort_keys=True, indent=2))
    return 0 if all(r["reproduced"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
