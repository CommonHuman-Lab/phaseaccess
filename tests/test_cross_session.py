# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for _check_direct_cross_session() in phaseaccess.engine.scanner."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from phaseaccess.engine.reporter import Confidence, IDORType
from phaseaccess.engine.fingerprint import ResponseFingerprint
from phaseaccess.engine.scanner import _check_direct_cross_session, ScanOptions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fp(
    status: int = 200,
    body: str = '{"user_id": "alice-uid-1234567890", "email": "alice@example.com"}',
    ownership: dict | None = None,
) -> ResponseFingerprint:
    fp = ResponseFingerprint(url="https://api.example.com/users/1", method="GET",
                              status=status, body=body, headers={})
    fp.content_type = "application/json"
    fp.body_length = len(body)
    fp.stable_hash = "aabbcc"
    fp.json_keys = []
    fp.ownership_values = ownership if ownership is not None else {}
    fp.structure_sig = ""
    fp.elapsed_ms = 10.0
    return fp


def _make_opts(**kwargs) -> ScanOptions:
    return ScanOptions(**kwargs)


# ---------------------------------------------------------------------------
# _check_direct_cross_session
# ---------------------------------------------------------------------------

class TestCheckDirectCrossSession:
    def test_returns_none_when_a_not_200(self):
        a = _make_fp(status=403)
        b = _make_fp(status=200)
        result = _check_direct_cross_session("https://api.example.com/users/1", a, b, _make_opts())
        assert result is None

    def test_returns_none_when_b_not_200(self):
        a = _make_fp(status=200)
        b = _make_fp(status=403)
        result = _check_direct_cross_session("https://api.example.com/users/1", a, b, _make_opts())
        assert result is None

    def test_returns_none_when_no_ownership_values(self):
        a = _make_fp(status=200, ownership={})
        b = _make_fp(status=200)
        result = _check_direct_cross_session("https://api.example.com/users/1", a, b, _make_opts())
        assert result is None

    def test_returns_none_when_ownership_value_too_short(self):
        # Values < 8 chars are ignored
        a = _make_fp(status=200, ownership={"id": "abc"})
        b = _make_fp(status=200, body="abc")
        result = _check_direct_cross_session("https://api.example.com/users/1", a, b, _make_opts())
        assert result is None

    def test_returns_none_when_value_not_in_b_body(self):
        a = _make_fp(status=200, ownership={"user_id": "alice-uid-1234567890"})
        b = _make_fp(status=200, body='{"user_id": "bob-uid-9999999999"}')
        result = _check_direct_cross_session("https://api.example.com/users/1", a, b, _make_opts())
        assert result is None

    def test_confirmed_finding_when_ownership_leaked(self):
        long_uid = "alice-uid-1234567890"
        a = _make_fp(status=200, ownership={"user_id": long_uid})
        b = _make_fp(status=200, body=f'{{"user_id": "{long_uid}", "email": "a@b.com"}}')
        with patch("phaseaccess.engine.extractor.extract_all", return_value=[]):
            result = _check_direct_cross_session(
                "https://api.example.com/users/1", a, b, _make_opts()
            )
        assert result is not None
        assert result.confidence == Confidence.CONFIRMED
        assert result.idor_type == IDORType.HORIZONTAL

    def test_leaked_fields_listed_in_finding(self):
        uid = "alice-uid-99887766"
        a = _make_fp(status=200, ownership={"user_id": uid, "email": "alice@example.com"})
        b = _make_fp(status=200, body=f'{{"user_id": "{uid}"}}')
        with patch("phaseaccess.engine.extractor.extract_all", return_value=[]):
            result = _check_direct_cross_session(
                "https://api.example.com/users/1", a, b, _make_opts()
            )
        assert result is not None
        assert "user_id" in result.owner_fields_leaked

    def test_finding_uses_first_ref_when_available(self):
        from phaseaccess.engine.extractor import ObjectRef
        from phaseaccess.engine.reporter import IDORLocation, IDType
        uid = "alice-uid-12345678"
        a = _make_fp(status=200, ownership={"user_id": uid})
        b = _make_fp(status=200, body=f'{{"user_id": "{uid}"}}')
        mock_ref = ObjectRef(
            location=IDORLocation.PATH_SEGMENT,
            param="id",
            value="1",
            id_type=IDType.INTEGER,
            url="https://api.example.com/users/1",
            method="GET",
        )
        with patch("phaseaccess.engine.scanner.extract_all", return_value=[mock_ref]):
            result = _check_direct_cross_session(
                "https://api.example.com/users/1", a, b, _make_opts()
            )
        assert result is not None
        assert result.parameter == "id"

    def test_finding_uses_direct_param_when_no_refs(self):
        uid = "alice-uid-12345678"
        a = _make_fp(status=200, ownership={"user_id": uid})
        b = _make_fp(status=200, body=f'{{"user_id": "{uid}"}}')
        with patch("phaseaccess.engine.extractor.extract_all", return_value=[]):
            result = _check_direct_cross_session(
                "https://api.example.com/dashboard", a, b, _make_opts()
            )
        assert result is not None
        assert result.parameter == "[direct]"

    def test_evidence_snippet_truncated_to_500(self):
        uid = "alice-uid-12345678"
        long_body = f'{{"user_id": "{uid}", "data": "' + "x" * 1000 + '"}'
        a = _make_fp(status=200, ownership={"user_id": uid})
        b = _make_fp(status=200, body=long_body)
        b.ownership_values = {}
        with patch("phaseaccess.engine.extractor.extract_all", return_value=[]):
            result = _check_direct_cross_session(
                "https://api.example.com/users/1", a, b, _make_opts()
            )
        if result:
            assert len(result.evidence_snippet) <= 500
