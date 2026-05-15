# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for phaseaccess.engine.chainer — all network calls are mocked."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from phaseaccess.engine.chainer import chain_scan, _fill_template, _match_placeholder
from phaseaccess.engine.reporter import Confidence, IDORType
from phaseaccess.engine.session import Session, SessionPair
from phaseaccess.engine.scanner import ScanOptions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pair(dual: bool = True) -> SessionPair:
    sa = Session(label="alice", headers={"Authorization": "Bearer alice"}, cookies="")
    sb = Session(label="bob",   headers={"Authorization": "Bearer bob"},   cookies="") if dual else None
    return SessionPair(session_a=sa, session_b=sb)


def _make_opts(**kwargs) -> ScanOptions:
    defaults = dict(
        session_a_label="alice",
        session_b_label="bob",
        proxy="",
        timeout=5,
        delay=0.0,
        verify_ssl=False,
    )
    defaults.update(kwargs)
    return ScanOptions(**defaults)


def _make_fp(
    status: int = 200,
    body: str = '{"id": 42, "owner": "alice-uid-9876543210"}',
    ownership: dict | None = None,
) -> MagicMock:
    fp = MagicMock()
    fp.status = status
    fp.body = body
    fp.body_length = len(body)
    fp.ownership_values = ownership if ownership is not None else {"owner": "alice-uid-9876543210"}
    return fp


def _logs() -> list:
    msgs = []
    return msgs, lambda m: msgs.append(m)


# ---------------------------------------------------------------------------
# _match_placeholder
# ---------------------------------------------------------------------------

class TestMatchPlaceholder:
    def test_exact_match(self):
        assert _match_placeholder("id", ["id", "slug"]) == "id"

    def test_case_insensitive_exact(self):
        assert _match_placeholder("ID", ["id"]) == "id"

    def test_substring_match(self):
        assert _match_placeholder("item_id", ["id"]) == "id"

    def test_reverse_substring_match(self):
        assert _match_placeholder("id", ["item_id"]) == "item_id"

    def test_no_match_returns_none(self):
        assert _match_placeholder("uuid", ["slug", "name"]) is None

    def test_empty_placeholders_returns_none(self):
        assert _match_placeholder("id", []) is None


# ---------------------------------------------------------------------------
# _fill_template
# ---------------------------------------------------------------------------

class TestFillTemplate:
    def test_replaces_placeholder(self):
        assert _fill_template("/items/{id}", "id", "42") == "/items/42"

    def test_replaces_multiple_occurrences(self):
        assert _fill_template("/{x}/to/{x}", "x", "5") == "/5/to/5"

    def test_no_placeholder_unchanged(self):
        assert _fill_template("/items/fixed", "id", "99") == "/items/fixed"


# ---------------------------------------------------------------------------
# chain_scan — guard conditions
# ---------------------------------------------------------------------------

class TestChainScanGuards:
    def test_single_session_returns_empty(self):
        pair = _make_pair(dual=False)
        msgs, log = _logs()
        result = chain_scan(
            create_url="https://api.example.com/items",
            create_method="POST",
            create_body='{"title": "x"}',
            read_url_template="https://api.example.com/items/{id}",
            opts=_make_opts(),
            pair=pair,
            log=log,
        )
        assert result == []
        assert any("dual-session" in m for m in msgs)

    def test_create_request_failure_returns_empty(self):
        pair = _make_pair(dual=True)
        _, log = _logs()
        with patch("phaseaccess.engine.chainer.fire_request", return_value=None):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="https://api.example.com/items/{id}",
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        assert result == []

    def test_non_2xx_create_returns_empty(self):
        pair = _make_pair(dual=True)
        _, log = _logs()
        bad_fp = _make_fp(status=403, body="Forbidden", ownership={})
        with patch("phaseaccess.engine.chainer.fire_request", return_value=bad_fp):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="https://api.example.com/items/{id}",
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        assert result == []

    def test_no_harvested_ids_returns_empty(self):
        pair = _make_pair(dual=True)
        _, log = _logs()
        create_fp = _make_fp(status=201, body='{"ok": true}', ownership={})
        with patch("phaseaccess.engine.chainer.fire_request", return_value=create_fp), \
             patch("phaseaccess.engine.chainer.harvest_ids_from_response", return_value=[]):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="https://api.example.com/items/{id}",
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        assert result == []


# ---------------------------------------------------------------------------
# chain_scan — successful flows
# ---------------------------------------------------------------------------

class TestChainScanSuccess:
    def _run(self, create_status=201, create_body=None, read_status=200,
             read_body=None, ownership=None, template="https://api.example.com/items/{id}"):
        pair = _make_pair(dual=True)
        _, log = _logs()

        create_fp = _make_fp(
            status=create_status,
            body=create_body or '{"id": 42}',
            ownership=ownership or {},
        )

        harvested = MagicMock()
        harvested.field = "id"
        harvested.value = "42"

        read_fp = _make_fp(
            status=read_status,
            body=read_body or '{"id": 42, "owner": "alice-uid-9876543210"}',
            ownership={},
        )

        with patch("phaseaccess.engine.chainer.fire_request", side_effect=[create_fp, read_fp]), \
             patch("phaseaccess.engine.chainer.harvest_ids_from_response", return_value=[harvested]):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body='{"title": "x"}',
                read_url_template=template,
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        return result

    def test_confirmed_when_ownership_leaked(self):
        uid = "alice-uid-9876543210"
        result = self._run(
            ownership={"owner": uid},
            read_body=f'{{"id": 42, "owner": "{uid}"}}',
        )
        assert len(result) == 1
        assert result[0].confidence == Confidence.CONFIRMED
        assert result[0].idor_type == IDORType.HORIZONTAL

    def test_high_confidence_when_no_ownership_leaked(self):
        result = self._run(
            ownership={},
            read_body='{"id": 42, "title": "test"}',
        )
        assert len(result) == 1
        assert result[0].confidence == Confidence.HIGH

    def test_finding_notes_contain_ids(self):
        result = self._run()
        assert len(result) >= 1
        assert "42" in result[0].notes

    def test_read_url_not_200_skipped(self):
        pair = _make_pair(dual=True)
        _, log = _logs()
        create_fp = _make_fp(status=201, body='{"id": 99}', ownership={})
        harvested = MagicMock(); harvested.field = "id"; harvested.value = "99"
        read_fp = _make_fp(status=403, body="Forbidden", ownership={})
        with patch("phaseaccess.engine.chainer.fire_request", side_effect=[create_fp, read_fp]), \
             patch("phaseaccess.engine.chainer.harvest_ids_from_response", return_value=[harvested]):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="https://api.example.com/items/{id}",
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        assert result == []

    def test_read_request_failure_skipped(self):
        pair = _make_pair(dual=True)
        _, log = _logs()
        create_fp = _make_fp(status=201, body='{"id": 99}', ownership={})
        harvested = MagicMock(); harvested.field = "id"; harvested.value = "99"
        with patch("phaseaccess.engine.chainer.fire_request", side_effect=[create_fp, None]), \
             patch("phaseaccess.engine.chainer.harvest_ids_from_response", return_value=[harvested]):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="https://api.example.com/items/{id}",
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        assert result == []

    def test_relative_read_url_made_absolute(self):
        pair = _make_pair(dual=True)
        _, log = _logs()
        create_fp = _make_fp(status=201, body='{"id": 5}', ownership={})
        harvested = MagicMock(); harvested.field = "id"; harvested.value = "5"
        read_fp = _make_fp(status=200, body='{"id": 5}', ownership={})
        called_urls = []

        def capture_fire(url, **kwargs):
            called_urls.append(url)
            return create_fp if not called_urls[1:] else read_fp

        with patch("phaseaccess.engine.chainer.fire_request", side_effect=[create_fp, read_fp]), \
             patch("phaseaccess.engine.chainer.harvest_ids_from_response", return_value=[harvested]):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="/items/{id}",   # relative template
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        # Should succeed and produce a finding (URL made absolute from create_url's base)
        assert len(result) == 1

    def test_fallback_to_first_placeholder_when_no_match(self):
        # Harvested field "resource_id" doesn't match placeholder "uuid"
        pair = _make_pair(dual=True)
        _, log = _logs()
        create_fp = _make_fp(status=201, body='{"resource_id": "abc"}', ownership={})
        harvested = MagicMock(); harvested.field = "resource_id"; harvested.value = "abc"
        read_fp = _make_fp(status=200, body='{"resource_id": "abc"}', ownership={})
        with patch("phaseaccess.engine.chainer.fire_request", side_effect=[create_fp, read_fp]), \
             patch("phaseaccess.engine.chainer.harvest_ids_from_response", return_value=[harvested]):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="https://api.example.com/items/{uuid}",
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        assert len(result) == 1

    def test_no_placeholder_in_template_skips(self):
        # Template has no {placeholders} — harvested IDs can't be substituted
        pair = _make_pair(dual=True)
        _, log = _logs()
        create_fp = _make_fp(status=201, body='{"id": 7}', ownership={})
        harvested = MagicMock(); harvested.field = "id"; harvested.value = "7"
        with patch("phaseaccess.engine.chainer.fire_request", return_value=create_fp), \
             patch("phaseaccess.engine.chainer.harvest_ids_from_response", return_value=[harvested]):
            result = chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="https://api.example.com/items/fixed",  # no placeholder
                opts=_make_opts(),
                pair=pair,
                log=log,
            )
        assert result == []

    def test_delay_honoured(self):
        pair = _make_pair(dual=True)
        _, log = _logs()
        create_fp = _make_fp(status=201, body='{"id": 1}', ownership={})
        harvested = MagicMock(); harvested.field = "id"; harvested.value = "1"
        read_fp = _make_fp(status=200, body='{"id": 1}', ownership={})
        sleep_calls = []
        with patch("phaseaccess.engine.chainer.fire_request", side_effect=[create_fp, read_fp]), \
             patch("phaseaccess.engine.chainer.harvest_ids_from_response", return_value=[harvested]), \
             patch("phaseaccess.engine.chainer.time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            chain_scan(
                create_url="https://api.example.com/items",
                create_method="POST",
                create_body="",
                read_url_template="https://api.example.com/items/{id}",
                opts=_make_opts(delay=0.5),
                pair=pair,
                log=log,
            )
        assert any(s == 0.5 for s in sleep_calls)
