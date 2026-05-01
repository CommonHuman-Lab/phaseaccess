"""
Tests for the three new IDOR detection checks:
  - BLIND  (_check_blind_idor)
  - MASS_ASSIGNMENT (_check_mass_assignment)
  - SOFT_DELETE (_check_soft_delete)
"""
import pytest
from unittest.mock import patch, MagicMock

from phaseaccess.engine.reporter import (
    IDORType, Confidence, IDORLocation, IDType,
)
from phaseaccess.engine.fingerprint import ResponseFingerprint
from phaseaccess.engine.extractor import ObjectRef
from phaseaccess.engine.scanner import (
    _check_blind_idor,
    _check_mass_assignment,
    _check_soft_delete,
    ScanOptions,
    _SOFT_DELETE_HINTS,
)
from phaseaccess.engine.session import Session, SessionPair


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fp(
    status: int = 200,
    body: str = '{"id": 1}',
    headers: dict = None,
    url: str = "https://api.example.com/resource/1",
    stable_hash: str = "aabbccdd",
) -> ResponseFingerprint:
    fp = ResponseFingerprint(
        url=url,
        method="GET",
        status=status,
        body=body,
        headers=headers or {},
    )
    fp.content_type = "application/json"
    fp.body_length = len(body)
    fp.stable_hash = stable_hash
    fp.json_keys = []
    fp.ownership_values = {}
    fp.structure_sig = ""
    fp.elapsed_ms = 10.0
    return fp


def _make_ref(
    location: IDORLocation = IDORLocation.QUERY_PARAM,
    param: str = "id",
    value: str = "42",
    url: str = "https://api.example.com/resource/42",
    method: str = "GET",
    body_context=None,
) -> ObjectRef:
    return ObjectRef(
        location=location,
        param=param,
        value=value,
        id_type=IDType.INTEGER,
        url=url,
        method=method,
        body_context=body_context,
    )


def _make_pair() -> SessionPair:
    sa = Session(label="session_a", headers={}, cookies="token=abc")
    return SessionPair(session_a=sa, session_b=None)


def _make_opts(**kwargs) -> ScanOptions:
    opts = ScanOptions(**kwargs)
    return opts


# ---------------------------------------------------------------------------
# _check_blind_idor
# ---------------------------------------------------------------------------

class TestCheckBlindIdor:

    def test_403_to_200_no_body_is_blind(self):
        baseline = _make_fp(status=403, body="Forbidden")
        tampered = _make_fp(status=200, body="")
        tampered.body_length = 0
        ref = _make_ref()
        finding = _check_blind_idor(ref, baseline, tampered, "admin", "test")
        assert finding is not None
        assert finding.idor_type == IDORType.BLIND
        assert finding.confidence == Confidence.MEDIUM

    def test_404_to_204_no_body_is_blind(self):
        baseline = _make_fp(status=404, body="Not Found")
        tampered = _make_fp(status=204, body="")
        tampered.body_length = 0
        ref = _make_ref()
        finding = _check_blind_idor(ref, baseline, tampered, "1", "desc")
        assert finding is not None
        assert finding.idor_type == IDORType.BLIND

    def test_403_to_200_with_large_body_not_blind(self):
        """If there is substantial body content, normal comparator handles it."""
        baseline = _make_fp(status=403)
        tampered = _make_fp(status=200, body='{"user_id": 99, "email": "a@b.com"}')
        tampered.body_length = 200
        ref = _make_ref()
        finding = _check_blind_idor(ref, baseline, tampered, "99", "desc")
        assert finding is None

    def test_200_to_200_not_blind(self):
        baseline = _make_fp(status=200)
        tampered = _make_fp(status=200, body="")
        tampered.body_length = 0
        ref = _make_ref()
        finding = _check_blind_idor(ref, baseline, tampered, "99", "desc")
        assert finding is None

    def test_403_to_500_not_blind(self):
        """500 is not an access code."""
        baseline = _make_fp(status=403)
        tampered = _make_fp(status=500, body="")
        tampered.body_length = 0
        ref = _make_ref()
        finding = _check_blind_idor(ref, baseline, tampered, "1", "desc")
        assert finding is None

    def test_401_to_201_no_body_is_blind(self):
        baseline = _make_fp(status=401)
        tampered = _make_fp(status=201, body="")
        tampered.body_length = 0
        ref = _make_ref()
        finding = _check_blind_idor(ref, baseline, tampered, "x", "desc")
        assert finding is not None
        assert finding.idor_type == IDORType.BLIND

    def test_finding_fields(self):
        baseline = _make_fp(status=403)
        tampered = _make_fp(status=200, body="")
        tampered.body_length = 0
        ref = _make_ref(param="user_id", value="10")
        finding = _check_blind_idor(ref, baseline, tampered, "99", "neighbour")
        assert finding.parameter == "user_id"
        assert finding.original_value == "10"
        assert finding.tampered_value == "99"
        assert finding.baseline_status == 403
        assert finding.tampered_status == 200
        assert "blind IDOR" in finding.notes

    def test_short_body_still_blind(self):
        """Bodies up to 100 bytes are still considered 'no body'."""
        baseline = _make_fp(status=404)
        tampered = _make_fp(status=200, body="ok")
        tampered.body_length = 2
        ref = _make_ref()
        finding = _check_blind_idor(ref, baseline, tampered, "1", "desc")
        assert finding is not None

    def test_exactly_100_bytes_not_blind(self):
        """body_length > 100 means normal comparator handles it."""
        baseline = _make_fp(status=403)
        tampered = _make_fp(status=200, body="x" * 101)
        tampered.body_length = 101
        ref = _make_ref()
        finding = _check_blind_idor(ref, baseline, tampered, "1", "desc")
        assert finding is None


# ---------------------------------------------------------------------------
# _check_mass_assignment
# ---------------------------------------------------------------------------

class TestCheckMassAssignment:

    def _make_comparator_result(self, verdict, confidence, signals=None):
        from phaseaccess.engine.comparator import DiffResult, DiffVerdict
        return DiffResult(
            verdict=verdict,
            confidence=confidence,
            signals=signals or ["body changed"],
            leaked_fields=[],
            evidence_snippet='{"owner_id": "999"}',
        )

    def test_non_json_body_returns_none(self):
        """Mass assignment only applies to JSON/POST body refs."""
        ref = _make_ref(location=IDORLocation.QUERY_PARAM)
        baseline = _make_fp()
        opts = _make_opts()
        pair = _make_pair()
        result = _check_mass_assignment(ref, baseline, "999", opts, pair)
        assert result is None

    def test_no_foreign_id_returns_none(self):
        ref = _make_ref(location=IDORLocation.JSON_BODY, body_context={"name": "doc"})
        baseline = _make_fp()
        opts = _make_opts()
        pair = _make_pair()
        result = _check_mass_assignment(ref, baseline, "", opts, pair)
        assert result is None

    def test_json_body_confirmed_returns_finding(self):
        from phaseaccess.engine.comparator import DiffVerdict
        ref = _make_ref(
            location=IDORLocation.JSON_BODY,
            body_context={"name": "doc"},
            method="POST",
        )
        baseline = _make_fp(status=200, body='{"id": 1, "name": "doc"}')
        opts = _make_opts()
        pair = _make_pair()

        diff_result = self._make_comparator_result(
            DiffVerdict.CONFIRMED, Confidence.CONFIRMED
        )
        fp_with_injection = _make_fp(
            status=200,
            body='{"id": 1, "name": "doc", "owner_id": "999"}',
        )

        with patch("phaseaccess.engine.scanner._do_single_request", return_value=fp_with_injection), \
             patch("phaseaccess.engine.scanner.compare", return_value=diff_result):
            result = _check_mass_assignment(ref, baseline, "999", opts, pair)

        assert result is not None
        assert result.idor_type == IDORType.MASS_ASSIGNMENT
        assert result.confidence == Confidence.CONFIRMED

    def test_network_failure_returns_none(self):
        ref = _make_ref(location=IDORLocation.JSON_BODY, body_context={"x": 1})
        baseline = _make_fp()
        opts = _make_opts()
        pair = _make_pair()
        with patch("phaseaccess.engine.scanner._do_single_request", return_value=None):
            result = _check_mass_assignment(ref, baseline, "999", opts, pair)
        assert result is None

    def test_diff_not_idor_returns_none(self):
        from phaseaccess.engine.comparator import DiffVerdict, DiffResult
        ref = _make_ref(location=IDORLocation.JSON_BODY, body_context={"x": 1})
        baseline = _make_fp()
        opts = _make_opts()
        pair = _make_pair()
        no_diff = DiffResult(
            verdict=DiffVerdict.UNCHANGED,
            confidence=Confidence.INFO,
            signals=[],
            leaked_fields=[],
            evidence_snippet="",
        )
        fp = _make_fp(status=200, body='{"x": 1}')
        with patch("phaseaccess.engine.scanner._do_single_request", return_value=fp), \
             patch("phaseaccess.engine.scanner.compare", return_value=no_diff):
            result = _check_mass_assignment(ref, baseline, "999", opts, pair)
        assert result is None

    def test_injected_value_reflected_upgrades_confidence(self):
        """If the foreign ID appears in response body, confidence >= HIGH."""
        from phaseaccess.engine.comparator import DiffVerdict, DiffResult
        ref = _make_ref(location=IDORLocation.JSON_BODY, body_context={"x": 1})
        baseline = _make_fp()
        opts = _make_opts()
        pair = _make_pair()
        possible_diff = DiffResult(
            verdict=DiffVerdict.POSSIBLE,
            confidence=Confidence.LOW,
            signals=["body changed"],
            leaked_fields=[],
            evidence_snippet="",
        )
        # Body contains the injected foreign id "FOREIGN123"
        fp = _make_fp(status=200, body='{"owner_id": "FOREIGN123"}')
        with patch("phaseaccess.engine.scanner._do_single_request", return_value=fp), \
             patch("phaseaccess.engine.scanner.compare", return_value=possible_diff):
            result = _check_mass_assignment(ref, baseline, "FOREIGN123", opts, pair)
        assert result is not None
        assert result.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
        assert "reflected" in result.notes

    def test_post_body_ref_also_tested(self):
        """POST_BODY location should also trigger the check."""
        from phaseaccess.engine.comparator import DiffVerdict, DiffResult
        ref = _make_ref(
            location=IDORLocation.POST_BODY,
            body_context="name=doc&user_id=1",
            method="POST",
        )
        baseline = _make_fp()
        opts = _make_opts()
        pair = _make_pair()
        diff = DiffResult(
            verdict=DiffVerdict.LIKELY,
            confidence=Confidence.HIGH,
            signals=["body changed"],
            leaked_fields=[],
            evidence_snippet="",
        )
        fp = _make_fp(status=200, body='{"accepted": true}')
        with patch("phaseaccess.engine.scanner._do_single_request", return_value=fp), \
             patch("phaseaccess.engine.scanner.compare", return_value=diff):
            result = _check_mass_assignment(ref, baseline, "999", opts, pair)
        assert result is not None
        assert result.idor_type == IDORType.MASS_ASSIGNMENT


# ---------------------------------------------------------------------------
# _check_soft_delete
# ---------------------------------------------------------------------------

class TestCheckSoftDelete:

    def test_404_baseline_returns_200_is_finding(self):
        ref = _make_ref()
        baseline = _make_fp(status=404, body="Not Found")
        opts = _make_opts()
        pair = _make_pair()

        # First hint returns 200 with a body
        revealed_fp = _make_fp(
            status=200,
            body='{"id": 42, "name": "deleted-doc", "deleted": true, "extra": "data"}',
        )
        revealed_fp.body_length = len(revealed_fp.body)

        with patch("phaseaccess.engine.scanner._do_single_request", return_value=revealed_fp):
            result = _check_soft_delete(ref, baseline, opts, pair)

        assert result is not None
        assert result.idor_type == IDORType.SOFT_DELETE
        assert result.confidence == Confidence.HIGH
        assert result.baseline_status == 404
        assert result.tampered_status == 200

    def test_no_hint_triggers_returns_none(self):
        ref = _make_ref()
        baseline = _make_fp(status=200)
        opts = _make_opts()
        pair = _make_pair()

        # All hint requests return same 200 with same small body
        tiny_fp = _make_fp(status=200, body='{"x":1}')
        tiny_fp.body_length = 7
        tiny_fp.stable_hash = baseline.stable_hash  # unchanged

        with patch("phaseaccess.engine.scanner._do_single_request", return_value=tiny_fp):
            result = _check_soft_delete(ref, baseline, opts, pair)

        assert result is None

    def test_network_failure_on_all_hints_returns_none(self):
        ref = _make_ref()
        baseline = _make_fp(status=404)
        opts = _make_opts()
        pair = _make_pair()
        with patch("phaseaccess.engine.scanner._do_single_request", return_value=None):
            result = _check_soft_delete(ref, baseline, opts, pair)
        assert result is None

    def test_200_baseline_significant_growth_is_medium(self):
        ref = _make_ref()
        baseline = _make_fp(status=200, body='{"id": 1}')
        baseline.body_length = 9
        opts = _make_opts()
        pair = _make_pair()

        # Response with >30% more content and different hash
        grown_fp = _make_fp(
            status=200,
            body='{"id": 1, "deleted_items": [{"id": 2}, {"id": 3}]}',
            stable_hash="different_hash",
        )
        grown_fp.body_length = len(grown_fp.body)

        with patch("phaseaccess.engine.scanner._do_single_request", return_value=grown_fp):
            result = _check_soft_delete(ref, baseline, opts, pair)

        assert result is not None
        assert result.idor_type == IDORType.SOFT_DELETE
        assert result.confidence == Confidence.MEDIUM

    def test_200_baseline_tiny_growth_not_finding(self):
        """Growth must be > 30% to qualify."""
        ref = _make_ref()
        baseline = _make_fp(status=200, body='{"id": 1, "name": "doc"}')
        baseline.body_length = len(baseline.body)
        opts = _make_opts()
        pair = _make_pair()

        # Only 5% larger — not significant
        small_fp = _make_fp(
            status=200,
            body='{"id": 1, "name": "document"}',
            stable_hash="other_hash",
        )
        small_fp.body_length = len(small_fp.body)

        with patch("phaseaccess.engine.scanner._do_single_request", return_value=small_fp):
            result = _check_soft_delete(ref, baseline, opts, pair)

        assert result is None

    def test_404_to_200_with_tiny_body_not_finding(self):
        """Body must be > 50 bytes to avoid false positives from empty 200s."""
        ref = _make_ref()
        baseline = _make_fp(status=404)
        opts = _make_opts()
        pair = _make_pair()

        small_fp = _make_fp(status=200, body="ok")
        small_fp.body_length = 2

        with patch("phaseaccess.engine.scanner._do_single_request", return_value=small_fp):
            result = _check_soft_delete(ref, baseline, opts, pair)

        assert result is None

    def test_finding_has_hint_param_in_notes(self):
        ref = _make_ref()
        baseline = _make_fp(status=404)
        opts = _make_opts()
        pair = _make_pair()

        good_fp = _make_fp(status=200, body="x" * 100)
        good_fp.body_length = 100

        with patch("phaseaccess.engine.scanner._do_single_request", return_value=good_fp):
            result = _check_soft_delete(ref, baseline, opts, pair)

        assert result is not None
        # The first hint param should appear in the notes
        first_param = _SOFT_DELETE_HINTS[0][0]
        assert first_param in result.notes
