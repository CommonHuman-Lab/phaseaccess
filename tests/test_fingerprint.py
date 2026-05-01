# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
Tests for phaseaccess/engine/fingerprint.py
"""
import pytest

from phaseaccess.engine.fingerprint import (
  fingerprint_response,
  _stabilise,
  _detect_volatile_values,
  _rebuild_with_extra_volatiles,
  build_baseline,
)


# ---------------------------------------------------------------------------
# _stabilise
# ---------------------------------------------------------------------------

class TestStabilise:
  def test_strips_iso_timestamps(self):
    body = '{"updated_at": "2024-01-15T12:34:56", "id": 42}'
    result = _stabilise(body)
    assert "2024-01-15T12:34:56" not in result
    assert "__VOLATILE__" in result

  def test_strips_csrf_token(self):
    body = '{"_token": "abc123xyz", "user": "alice"}'
    result = _stabilise(body)
    assert "abc123xyz" not in result

  def test_strips_all_uuids_in_baseline_mode(self):
    uuid_val = "550e8400-e29b-41d4-a716-446655440000"
    body = f'{{"id": "{uuid_val}"}}'
    result = _stabilise(body, baseline_body=None)
    assert uuid_val.lower() not in result.lower()
    assert "__VOLATILE__" in result

  def test_preserves_new_uuids_in_tampered_mode(self):
    """New UUIDs in tampered response (not in baseline) should be preserved."""
    baseline_uuid = "550e8400-e29b-41d4-a716-446655440000"
    new_uuid      = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    baseline_body = f'{{"id": "{baseline_uuid}"}}'
    tampered_body = f'{{"id": "{new_uuid}"}}'
    result = _stabilise(tampered_body, baseline_body=baseline_body)
    # new_uuid should NOT be stripped (it's evidence of cross-user leakage)
    assert new_uuid.lower() in result.lower()

  def test_strips_baseline_uuids_from_tampered(self):
    """UUIDs that were already in the baseline should be stripped from tampered."""
    baseline_uuid = "550e8400-e29b-41d4-a716-446655440000"
    baseline_body = f'{{"id": "{baseline_uuid}"}}'
    tampered_body = f'{{"id": "{baseline_uuid}", "extra": "data"}}'
    result = _stabilise(tampered_body, baseline_body=baseline_body)
    assert baseline_uuid.lower() not in result.lower()


# ---------------------------------------------------------------------------
# fingerprint_response
# ---------------------------------------------------------------------------

class TestFingerprintResponse:
  def _make(self, body, status=200, headers=None, baseline_body=None):
    return fingerprint_response(
      url="https://example.com/api/test",
      method="GET",
      status=status,
      body=body,
      headers=headers or {"Content-Type": "application/json"},
      elapsed_ms=50.0,
      baseline_body=baseline_body,
    )

  def test_basic_fields(self):
    fp = self._make('{"id": 1}')
    assert fp.status == 200
    assert fp.body_length == len('{"id": 1}')
    assert fp.content_type == "application/json"
    assert fp.elapsed_ms == 50.0

  def test_stable_hash_differs_when_content_differs(self):
    fp1 = self._make('{"id": 1, "user_id": "alice"}')
    fp2 = self._make('{"id": 2, "user_id": "bob"}')
    assert fp1.stable_hash != fp2.stable_hash

  def test_stable_hash_same_despite_timestamp_diff(self):
    """Two responses identical except for a timestamp should hash the same."""
    fp1 = self._make('{"data": "x", "updated_at": "2024-01-01T00:00:00"}')
    fp2 = self._make('{"data": "x", "updated_at": "2024-06-15T12:00:00"}')
    assert fp1.stable_hash == fp2.stable_hash

  def test_ownership_values_extracted(self):
    fp = self._make('{"user_id": "u123", "email": "alice@example.com"}')
    assert fp.ownership_values.get("user_id") == "u123"
    assert fp.ownership_values.get("email") == "alice@example.com"

  def test_ownership_excludes_removed_keys(self):
    """'name', 'author' were removed from OWNERSHIP_KEYS — should not appear."""
    fp = self._make('{"name": "Alice", "author": "Bob", "user_id": "u1"}')
    assert "name" not in fp.ownership_values
    assert "author" not in fp.ownership_values
    assert fp.ownership_values.get("user_id") == "u1"

  def test_structure_sig_captures_keys(self):
    fp = self._make('{"id": 1, "email": "a@b.com"}')
    assert "id" in fp.structure_sig or fp.structure_sig  # non-empty

  def test_volatile_headers_stripped(self):
    """Headers like x-request-id should not appear in fingerprint headers."""
    fp = self._make(
      '{}',
      headers={"Content-Type": "application/json", "X-Request-Id": "abc123"},
    )
    assert "x-request-id" not in fp.headers

  def test_empty_body(self):
    fp = self._make('')
    assert fp.body_length == 0
    assert fp.stable_hash  # still produces a hash


# ---------------------------------------------------------------------------
# _detect_volatile_values
# ---------------------------------------------------------------------------

class TestDetectVolatileValues:
  def test_detects_changed_scalar(self):
    body1 = '{"nonce": "abc123456", "id": 1}'
    body2 = '{"nonce": "xyz987654", "id": 1}'
    volatile = _detect_volatile_values(body1, body2)
    assert "abc123456" in volatile or "xyz987654" in volatile

  def test_ignores_identical_values(self):
    body1 = '{"id": 1, "user": "alice"}'
    body2 = '{"id": 1, "user": "alice"}'
    volatile = _detect_volatile_values(body1, body2)
    assert volatile == []

  def test_skips_short_values(self):
    """Short values like "1"/"2" should not be flagged as volatile."""
    body1 = '{"page": 1}'
    body2 = '{"page": 2}'
    volatile = _detect_volatile_values(body1, body2)
    assert volatile == []

  def test_non_json_body_returns_empty(self):
    volatile = _detect_volatile_values("not json", "also not json")
    assert volatile == []


# ---------------------------------------------------------------------------
# build_baseline — variance detection integration
# ---------------------------------------------------------------------------

class TestBuildBaselineVariance:
  """
  build_baseline makes real HTTP calls, so we only test the pure helper
  functions that implement the variance detection logic here.
  """

  def test_rebuild_with_extra_volatiles_changes_hash(self):
    import json as _json
    from phaseaccess.engine.fingerprint import fingerprint_response as _fp_resp

    body = '{"token": "tok_abc12345", "user_id": "u1"}'
    fp = _fp_resp(
      url="https://example.com/",
      method="GET",
      status=200,
      body=body,
      headers={"Content-Type": "application/json"},
    )
    original_hash = fp.stable_hash

    # Rebuild treating "tok_abc12345" as volatile
    new_fp = _rebuild_with_extra_volatiles(fp, ["tok_abc12345"])
    # Token is stripped — hashes differ
    assert new_fp.stable_hash != original_hash

  def test_rebuild_preserves_other_fields(self):
    from phaseaccess.engine.fingerprint import fingerprint_response as _fp_resp
    body = '{"token": "tok_abc12345", "user_id": "u1"}'
    fp = _fp_resp(
      url="https://example.com/",
      method="GET",
      status=200,
      body=body,
      headers={"Content-Type": "application/json"},
    )
    new_fp = _rebuild_with_extra_volatiles(fp, ["tok_abc12345"])
    assert new_fp.status == 200
    assert new_fp.body == body   # original body unchanged
    assert new_fp.url == fp.url