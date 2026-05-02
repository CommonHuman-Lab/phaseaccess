# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""Tests for _jwt_candidates() in phaseaccess.engine.id_engine."""

from __future__ import annotations

import base64
import json

import pytest

from phaseaccess.engine.id_engine import _jwt_candidates, generate_candidates
from phaseaccess.engine.reporter import IDType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _make_jwt(header: dict, payload: dict, sig: str = "fakesig") -> str:
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) == 3
    return json.loads(_b64_decode(parts[1]))


def _decode_jwt_header(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) == 3
    return json.loads(_b64_decode(parts[0]))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestJwtCandidates:
    def _header(self):
        return {"alg": "HS256", "typ": "JWT"}

    def test_returns_candidates_for_valid_jwt(self):
        token = _make_jwt(self._header(), {"sub": "42", "role": "user"})
        candidates = _jwt_candidates(token)
        assert len(candidates) > 0

    def test_alg_none_candidate_produced(self):
        token = _make_jwt(self._header(), {"sub": "1"})
        candidates = _jwt_candidates(token)
        alg_none = [c for c in candidates if "alg=none" in c.description]
        assert len(alg_none) >= 1, "Should produce an alg:none candidate"

    def test_alg_none_token_structure(self):
        """alg:none token must have an empty signature segment (trailing dot)."""
        token = _make_jwt(self._header(), {"sub": "1"})
        candidates = _jwt_candidates(token)
        alg_none_candidates = [c for c in candidates if "alg=none" in c.description]
        for cand in alg_none_candidates:
            assert cand.value.endswith("."), (
                f"alg:none token must end with '.' (empty sig), got: {cand.value}"
            )
            hdr = _decode_jwt_header(cand.value)
            assert hdr["alg"].lower() in ("none", "None"), (
                f"header alg should be 'none', got {hdr['alg']!r}"
            )

    def test_integer_sub_claim_mutation(self):
        token = _make_jwt(self._header(), {"sub": 10, "iat": 1700000000})
        candidates = _jwt_candidates(token)
        mutated_payloads = []
        for c in candidates:
            if "sub=" in c.description and "→" in c.description:
                mutated_payloads.append(_decode_jwt_payload(c.value))
        assert len(mutated_payloads) > 0
        sub_values = {p["sub"] for p in mutated_payloads}
        # Should contain sub+1 and/or sub-1
        assert 11 in sub_values or 9 in sub_values, (
            f"Expected integer sub mutations (9 or 11), got: {sub_values}"
        )

    def test_string_digit_sub_claim_mutation(self):
        token = _make_jwt(self._header(), {"sub": "42"})
        candidates = _jwt_candidates(token)
        subs = set()
        for c in candidates:
            if "sub=" in c.description and "→" in c.description:
                subs.add(_decode_jwt_payload(c.value)["sub"])
        assert "43" in subs or "41" in subs, f"Expected string sub mutations, got: {subs}"

    def test_user_id_claim_mutation(self):
        token = _make_jwt(self._header(), {"user_id": 5})
        candidates = _jwt_candidates(token)
        user_id_mutations = [c for c in candidates if "user_id=" in c.description]
        assert len(user_id_mutations) > 0

    def test_role_escalation_to_admin_string(self):
        token = _make_jwt(self._header(), {"sub": "1", "role": "user"})
        candidates = _jwt_candidates(token)
        role_cands = [c for c in candidates if "role" in c.description and "admin" in c.description]
        assert len(role_cands) >= 1
        for c in role_cands:
            payload = _decode_jwt_payload(c.value)
            assert payload["role"] == "admin", f"Expected role=admin, got {payload['role']!r}"

    def test_role_escalation_bool_set_true(self):
        token = _make_jwt(self._header(), {"sub": "1", "is_admin": False})
        candidates = _jwt_candidates(token)
        admin_cands = [c for c in candidates if "is_admin" in c.description]
        assert len(admin_cands) >= 1
        for c in admin_cands:
            payload = _decode_jwt_payload(c.value)
            assert payload["is_admin"] is True

    def test_role_list_gets_admin_appended(self):
        token = _make_jwt(self._header(), {"sub": "1", "roles": ["editor"]})
        candidates = _jwt_candidates(token)
        roles_cands = [c for c in candidates if "roles" in c.description]
        assert len(roles_cands) >= 1
        for c in roles_cands:
            payload = _decode_jwt_payload(c.value)
            assert "admin" in payload["roles"]

    def test_original_signature_preserved_in_claim_tamper(self):
        """Claim-tampered tokens with original sig should keep the original sig segment."""
        sig = "thisisthesignature"
        token = _make_jwt(self._header(), {"sub": "7"}, sig=sig)
        candidates = _jwt_candidates(token)
        orig_sig_cands = [c for c in candidates if "original sig" in c.description]
        assert len(orig_sig_cands) > 0
        for c in orig_sig_cands:
            assert c.value.endswith(f".{sig}"), (
                f"Expected token to end with original sig, got: {c.value[-20:]}"
            )

    def test_empty_sig_variants_produced(self):
        """Some candidates should have an empty signature (tests if sig is checked)."""
        token = _make_jwt(self._header(), {"sub": "3"})
        candidates = _jwt_candidates(token)
        empty_sig_cands = [c for c in candidates if "empty sig" in c.description]
        assert len(empty_sig_cands) > 0
        for c in empty_sig_cands:
            assert c.value.endswith("."), f"Empty-sig token should end with '.', got: {c.value}"

    def test_invalid_jwt_returns_empty(self):
        """A value that is not a valid JWT should return no candidates."""
        candidates = _jwt_candidates("notajwt")
        assert candidates == []

    def test_two_part_token_returns_empty(self):
        candidates = _jwt_candidates("header.payload")
        assert candidates == []

    def test_malformed_base64_returns_empty(self):
        candidates = _jwt_candidates("!!!.???.**")
        assert candidates == []

    def test_payload_without_known_id_claims(self):
        """A JWT with no id-like claims still gets alg:none candidate."""
        token = _make_jwt(self._header(), {"iss": "example.com", "exp": 9999999999})
        candidates = _jwt_candidates(token)
        alg_none = [c for c in candidates if "alg=none" in c.description]
        assert len(alg_none) >= 1

    def test_only_one_claim_tampered_per_call(self):
        """Only the first matching id claim should be tampered (not multiple)."""
        token = _make_jwt(self._header(), {"sub": "1", "id": 99, "user_id": 5})
        candidates = _jwt_candidates(token)
        # Each candidate description should only reference ONE claim
        tamper_descriptions = [
            c.description for c in candidates
            if "→" in c.description
        ]
        # They should all reference the same first-matched claim key
        if tamper_descriptions:
            first_key = tamper_descriptions[0].split("=")[0].split()[-1]
            for desc in tamper_descriptions:
                assert desc.startswith(f"JWT {first_key}="), (
                    f"Multiple claims tampered in one call. Desc: {desc!r}"
                )

    def test_generate_candidates_includes_jwt_results(self):
        """generate_candidates() with IDType.JWT should delegate to _jwt_candidates."""
        token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "100"})
        candidates = generate_candidates(token, IDType.JWT, count=20)
        values = [c.value for c in candidates]
        # At least the alg:none candidate should be present
        assert any(v.endswith(".") and v.count(".") == 2 for v in values), (
            "Expected at least one alg:none or empty-sig candidate"
        )
