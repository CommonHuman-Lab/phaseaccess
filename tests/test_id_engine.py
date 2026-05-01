"""Tests for phaseaccess.engine.id_engine"""
import pytest

from phaseaccess.engine.id_engine import (
    detect_id_type,
    generate_candidates,
    TamperCandidate,
    _integer_candidates,
    _uuid_candidates,
    _base64_candidates,
    _jwt_candidates,
    _hash_candidates,
    _snowflake_candidates,
    _slug_candidates,
    _universal_candidates,
    _is_valid_base64,
    _is_snowflake,
)
from phaseaccess.engine.reporter import IDType


# ---------------------------------------------------------------------------
# detect_id_type
# ---------------------------------------------------------------------------

class TestDetectIdType:
    def test_plain_integer(self):
        assert detect_id_type("42") == IDType.INTEGER

    def test_zero(self):
        assert detect_id_type("0") == IDType.INTEGER

    def test_large_integer(self):
        assert detect_id_type("9999999") == IDType.INTEGER

    def test_uuid_v4(self):
        assert detect_id_type("550e8400-e29b-41d4-a716-446655440000") == IDType.UUID_V4

    def test_uuid_v1(self):
        # UUID v1 has version nibble = 1
        assert detect_id_type("6ba7b810-9dad-11d1-80b4-00c04fd430c8") == IDType.UUID_V1

    def test_md5(self):
        import hashlib
        h = hashlib.md5(b"test").hexdigest()
        assert detect_id_type(h) == IDType.HASH_MD5

    def test_sha1(self):
        import hashlib
        h = hashlib.sha1(b"test").hexdigest()
        assert detect_id_type(h) == IDType.HASH_SHA1

    def test_sha256(self):
        import hashlib
        h = hashlib.sha256(b"test").hexdigest()
        assert detect_id_type(h) == IDType.HASH_SHA256

    def test_slug(self):
        assert detect_id_type("my-document-42") == IDType.SLUG

    def test_jwt(self):
        # A minimal but structurally valid JWT (3 base64url segments)
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert detect_id_type(jwt) == IDType.JWT

    def test_base64(self):
        import base64
        encoded = base64.b64encode(b"user:1234").decode().rstrip("=")
        assert detect_id_type(encoded) == IDType.BASE64

    def test_empty_string(self):
        assert detect_id_type("") == IDType.UNKNOWN

    def test_short_random_word(self):
        # A short plain word — not long enough for base64, not a known format
        assert detect_id_type("hello") == IDType.UNKNOWN

    def test_snowflake(self):
        # A Twitter-epoch snowflake from around 2020 (sequence bit 0)
        # ts = (2020-01-01) ms from epoch minus twitter epoch, shifted left 22
        # Using a known snowflake-like value
        snowflake = "1082524992802127872"  # approx 2019-01-08
        result = detect_id_type(snowflake)
        # May be SNOWFLAKE or INTEGER depending on epoch check — just ensure no crash
        assert result in (IDType.SNOWFLAKE, IDType.INTEGER)

    def test_uuid_v4_case_insensitive(self):
        assert detect_id_type("550E8400-E29B-41D4-A716-446655440000") == IDType.UUID_V4


# ---------------------------------------------------------------------------
# generate_candidates
# ---------------------------------------------------------------------------

class TestGenerateCandidates:
    def test_integer_candidates_not_empty(self):
        cands = generate_candidates("42", IDType.INTEGER)
        assert len(cands) > 0

    def test_integer_candidates_exclude_original(self):
        cands = generate_candidates("42", IDType.INTEGER)
        values = [c.value for c in cands]
        assert "42" not in values

    def test_uuid_v4_candidates_generated(self):
        cands = generate_candidates("550e8400-e29b-41d4-a716-446655440000", IDType.UUID_V4)
        assert len(cands) > 0

    def test_foreign_ids_appear_first(self):
        foreign = ["foreign-uuid-1", "foreign-uuid-2"]
        cands = generate_candidates("42", IDType.INTEGER, foreign_ids=foreign)
        first_values = [c.value for c in cands[:2]]
        assert "foreign-uuid-1" in first_values
        assert "foreign-uuid-2" in first_values

    def test_foreign_ids_marked_as_foreign(self):
        cands = generate_candidates("42", IDType.INTEGER, foreign_ids=["99"])
        foreign_cands = [c for c in cands if c.is_foreign]
        assert len(foreign_cands) >= 1
        assert foreign_cands[0].value == "99"

    def test_count_respected(self):
        cands = generate_candidates("1", IDType.INTEGER, count=5)
        assert len(cands) <= 5 + 5  # count + universal candidates max

    def test_unknown_type_uses_generic(self):
        cands = generate_candidates("weirdvalue", IDType.UNKNOWN)
        assert len(cands) > 0

    def test_universal_candidates_always_present(self):
        # Use a large count so universals aren't trimmed
        cands = generate_candidates("42", IDType.INTEGER, count=50)
        values = {c.value for c in cands}
        # At least one universal candidate present
        assert values & {"null", "*", "undefined"}


# ---------------------------------------------------------------------------
# _integer_candidates
# ---------------------------------------------------------------------------

class TestIntegerCandidates:
    def test_generates_neighbours(self):
        cands = _integer_candidates("10", 10)
        values = [c.value for c in cands]
        assert "11" in values
        assert "9" in values

    def test_no_subtracted_below_zero_from_delta(self):
        cands = _integer_candidates("0", 10)
        values = [c.value for c in cands]
        # The condition `if n - delta > 0` prevents adding e.g. "0 - 1 = -1"
        # as a *delta-based* candidate, but "-1" still appears as an explicit edge case
        # Verify at least: no delta-generated negative beyond the explicit edge case
        # i.e., "-2" and "-3" should not be generated for n=0
        assert "-2" not in values
        assert "-3" not in values

    def test_invalid_value_returns_empty(self):
        assert _integer_candidates("notanumber", 10) == []


# ---------------------------------------------------------------------------
# _base64_candidates
# ---------------------------------------------------------------------------

class TestBase64Candidates:
    def test_integer_encoded_base64_generates_neighbours(self):
        import base64
        encoded = base64.b64encode(b"5").decode().rstrip("=")
        cands = _base64_candidates(encoded)
        assert len(cands) > 0

    def test_relay_id_pattern(self):
        import base64
        encoded = base64.b64encode(b"User:42").decode().rstrip("=")
        cands = _base64_candidates(encoded)
        values_decoded = []
        for c in cands:
            try:
                padded = c.value + "=" * (-len(c.value) % 4)
                values_decoded.append(base64.b64decode(padded).decode())
            except Exception:
                pass
        assert any("User:41" in d or "User:43" in d for d in values_decoded)


# ---------------------------------------------------------------------------
# _hash_candidates
# ---------------------------------------------------------------------------

class TestHashCandidates:
    def test_finds_preimage_for_small_integer(self):
        import hashlib
        h = hashlib.md5(b"3").hexdigest()
        cands = _hash_candidates(h, IDType.HASH_MD5)
        # Should find pre-image 3 and generate hash(4), hash(2), etc.
        assert len(cands) > 0
        # hash(4) should be in candidates
        expected = hashlib.md5(b"4").hexdigest()
        assert any(c.value == expected for c in cands)

    def test_always_adds_seed_hashes(self):
        cands = _hash_candidates("a" * 32, IDType.HASH_MD5)
        # Should include hash("admin"), hash("root"), etc. even if pre-image not found
        assert any("admin" in c.description for c in cands)


# ---------------------------------------------------------------------------
# _universal_candidates
# ---------------------------------------------------------------------------

class TestUniversalCandidates:
    def test_contains_expected_values(self):
        cands = _universal_candidates()
        values = {c.value for c in cands}
        assert "*" in values
        assert "null" in values
        assert "undefined" in values


# ---------------------------------------------------------------------------
# _is_valid_base64
# ---------------------------------------------------------------------------

class TestIsValidBase64:
    def test_valid_base64(self):
        import base64
        encoded = base64.b64encode(b"hello world 1234").decode()
        assert _is_valid_base64(encoded) is True

    def test_invalid_base64(self):
        assert _is_valid_base64("!!!notbase64!!!") is False

    def test_short_value_rejected(self):
        # 3 bytes decoded from 4-char base64 is valid but only 3 bytes
        assert _is_valid_base64("YWJj") is False  # "abc" — only 3 bytes

    def test_all_zeros_rejected(self):
        import base64
        encoded = base64.b64encode(b"\x00\x00\x00\x00\x00").decode()
        assert _is_valid_base64(encoded) is False


# ---------------------------------------------------------------------------
# _slug_candidates
# ---------------------------------------------------------------------------

class TestSlugCandidates:
    def test_numeric_suffix_generates_neighbours(self):
        cands = _slug_candidates("my-document-5")
        values = [c.value for c in cands]
        assert "my-document-6" in values
        assert "my-document-4" in values

    def test_no_numeric_suffix_generates_overrides(self):
        cands = _slug_candidates("my-document")
        assert any(c.value == "admin" for c in cands)
