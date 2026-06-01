# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""Tests for phaseaccess.engine.comparator"""
import pytest

from phaseaccess.engine.fingerprint import ResponseFingerprint
from phaseaccess.engine.comparator import compare, DiffVerdict, _extract_snippet, _body_diff_snippet
from phaseaccess.engine.reporter import Confidence


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fp(
    status: int = 200,
    body: str = '{"id": 1, "email": "alice@example.com"}',
    structure_sig: str = "",
    ownership_values: dict | None = None,
    stable_hash: str = "abc123",
) -> ResponseFingerprint:
    return ResponseFingerprint(
        url="https://api.example.com/users/1",
        method="GET",
        status=status,
        body=body,
        headers={},
        body_length=len(body),
        stable_hash=stable_hash,
        structure_sig=structure_sig,
        ownership_values=ownership_values or {"email": "alice@example.com"},
    )


# ---------------------------------------------------------------------------
# Error verdict
# ---------------------------------------------------------------------------

class TestErrorVerdict:
    def test_tampered_status_zero_returns_error(self):
        baseline = _fp()
        tampered = _fp(status=0, body="", stable_hash="")
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.ERROR
        assert result.confidence == Confidence.LOW
        assert "tampered request failed" in result.signals


# ---------------------------------------------------------------------------
# Unchanged verdict
# ---------------------------------------------------------------------------

class TestUnchangedVerdict:
    def test_identical_responses_are_unchanged(self):
        baseline = _fp()
        tampered = _fp()  # same hash, same status
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.UNCHANGED

    def test_small_length_delta_not_flagged(self):
        baseline = _fp(body="x" * 100)
        tampered = _fp(body="x" * 140)  # delta 40, below threshold of 50
        # Same hash (we control it) — should be unchanged
        baseline.stable_hash = "hash1"
        tampered.stable_hash = "hash1"
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.UNCHANGED


# ---------------------------------------------------------------------------
# Confirmed verdict
# ---------------------------------------------------------------------------

class TestConfirmedVerdict:
    def test_ownership_field_value_changed_is_confirmed(self):
        baseline = _fp(ownership_values={"user_id": "1"})
        tampered = _fp(
            ownership_values={"user_id": "2"},
            stable_hash="different",
        )
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.CONFIRMED
        assert "user_id" in result.leaked_fields

    def test_known_foreign_value_in_response_is_confirmed(self):
        baseline = _fp(body='{"user": "alice"}', stable_hash="hashA")
        tampered = _fp(body='{"user": "bob@example.com"}', stable_hash="hashB")
        result = compare(
            baseline, tampered,
            known_foreign_values={"email": "bob@example.com"},
        )
        assert result.verdict == DiffVerdict.CONFIRMED
        assert any("CONFIRMED" in s for s in result.signals)


# ---------------------------------------------------------------------------
# Likely verdict
# ---------------------------------------------------------------------------

class TestLikelyVerdict:
    def test_ownership_field_appeared_with_hash_change_is_likely(self):
        baseline = _fp(ownership_values={})
        tampered = _fp(
            ownership_values={"user_id": "999"},
            stable_hash="different",
        )
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.LIKELY
        assert result.confidence == Confidence.HIGH

    def test_403_to_200_with_hash_change_is_likely(self):
        baseline = _fp(status=403, body='{"error":"forbidden"}', stable_hash="hashA",
                       ownership_values={})
        tampered = _fp(status=200, body='{"id":42,"data":"secret"}', stable_hash="hashB",
                       ownership_values={})
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.LIKELY
        assert result.confidence == Confidence.HIGH


# ---------------------------------------------------------------------------
# Possible verdict
# ---------------------------------------------------------------------------

class TestPossibleVerdict:
    def test_structural_change_is_possible(self):
        baseline = _fp(structure_sig="{id:int,name:str}", stable_hash="hashA",
                       ownership_values={})
        tampered = _fp(structure_sig="{id:int,name:str,role:str}", stable_hash="hashB",
                       ownership_values={})
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.POSSIBLE

    def test_large_length_delta_non_json_is_unchanged(self):
        # Plain-text body changes are intentionally not flagged as POSSIBLE —
        # HTML page differences (nav state, ads, recommendations) are too noisy
        # without a JSON structure or ownership-field signal. Use JSON bodies
        # with structure_sig to trigger the length-delta POSSIBLE verdict.
        baseline = _fp(body="a" * 100, stable_hash="hashA", ownership_values={})
        tampered = _fp(body="b" * 300, stable_hash="hashB", ownership_values={})
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.UNCHANGED

    def test_large_length_delta_json_is_possible(self):
        # JSON responses with large body change (delta > 100 bytes) DO trigger POSSIBLE
        small = '{"items":[1]}'
        large = '{"items":[' + ",".join(str(i) for i in range(50)) + ']}'
        assert len(large) - len(small) > 100
        baseline = _fp(body=small, stable_hash="hashA",
                       structure_sig="{items:arr}", ownership_values={})
        tampered = _fp(body=large, stable_hash="hashB",
                       structure_sig="{items:arr}", ownership_values={})
        result = compare(baseline, tampered)
        assert result.verdict in (DiffVerdict.POSSIBLE, DiffVerdict.LIKELY)

    def test_status_code_only_change_is_possible_low(self):
        baseline = _fp(status=200, stable_hash="same", ownership_values={})
        tampered = _fp(status=201, stable_hash="same", ownership_values={})
        result = compare(baseline, tampered)
        assert result.verdict == DiffVerdict.POSSIBLE
        assert result.confidence == Confidence.LOW


# ---------------------------------------------------------------------------
# Numeric deltas
# ---------------------------------------------------------------------------

class TestNumericDeltas:
    def test_status_delta_calculated(self):
        baseline = _fp(status=200, stable_hash="same")
        tampered = _fp(status=403, stable_hash="same")
        result = compare(baseline, tampered)
        assert result.status_delta == 203

    def test_length_delta_calculated(self):
        baseline = _fp(body="a" * 200, stable_hash="same")
        tampered = _fp(body="b" * 350, stable_hash="same")
        result = compare(baseline, tampered)
        assert result.length_delta == 150

    def test_length_ratio_calculated(self):
        baseline = _fp(body="a" * 100, stable_hash="same")
        tampered = _fp(body="b" * 200, stable_hash="same")
        result = compare(baseline, tampered)
        assert abs(result.length_ratio - 2.0) < 0.01


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_extract_snippet_basic(self):
        body = "before|needle|after"
        snippet = _extract_snippet(body, "needle", context=10)
        assert "needle" in snippet

    def test_extract_snippet_missing_needle(self):
        assert _extract_snippet("hello world", "nothere") == ""

    def test_body_diff_snippet_detects_change(self):
        a = '{"user": "alice"}'
        b = '{"user": "bob"}'
        snippet = _body_diff_snippet(a, b)
        assert snippet != ""

    def test_body_diff_snippet_identical(self):
        a = '{"user": "alice"}'
        snippet = _body_diff_snippet(a, a)
        assert snippet == ""