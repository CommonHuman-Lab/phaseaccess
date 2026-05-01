"""
Tests for phaseaccess/engine/session.py
"""
import pytest

from phaseaccess.engine.session import (
  Session,
  SessionPair,
  session_from_dict,
  pair_from_config,
)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class TestSession:
  def test_effective_headers_includes_own_headers(self):
    s = Session(label="test", headers={"X-Role": "admin"}, cookies="")
    h = s.effective_headers()
    assert h["X-Role"] == "admin"

  def test_effective_headers_sets_user_agent_default(self):
    s = Session(label="test")
    h = s.effective_headers()
    assert "User-Agent" in h
    assert h["User-Agent"] == "PhaseAccess/1.0"

  def test_effective_headers_does_not_override_ua(self):
    s = Session(label="test", headers={"User-Agent": "MyBot/2.0"})
    h = s.effective_headers()
    assert h["User-Agent"] == "MyBot/2.0"

  def test_effective_headers_adds_cookie(self):
    s = Session(label="test", cookies="session=abc123")
    h = s.effective_headers()
    assert h.get("Cookie") == "session=abc123"

  def test_effective_headers_extra_overrides(self):
    s = Session(label="test", headers={"X-Foo": "bar"})
    h = s.effective_headers(extra={"X-Foo": "baz", "X-New": "val"})
    assert h["X-Foo"] == "baz"
    assert h["X-New"] == "val"

  def test_empty_session(self):
    s = Session(label="anon")
    h = s.effective_headers()
    assert "Cookie" not in h


# ---------------------------------------------------------------------------
# SessionPair
# ---------------------------------------------------------------------------

class TestSessionPair:
  def _make_pair(self, with_b=True):
    a = Session(label="owner",   headers={"X-Token": "token_a"}, cookies="sess=A")
    b = Session(label="attacker", headers={"X-Token": "token_b"}, cookies="sess=B")
    return SessionPair(session_a=a, session_b=b if with_b else None)

  def test_is_dual_true_when_both_sessions(self):
    pair = self._make_pair(with_b=True)
    assert pair.is_dual is True

  def test_is_dual_false_when_only_a(self):
    pair = self._make_pair(with_b=False)
    assert pair.is_dual is False

  def test_headers_for_a(self):
    pair = self._make_pair()
    h = pair.headers_for('a')
    assert h["X-Token"] == "token_a"

  def test_headers_for_b(self):
    pair = self._make_pair()
    h = pair.headers_for('b')
    assert h["X-Token"] == "token_b"

  def test_headers_for_b_falls_back_to_a_when_no_b(self):
    pair = self._make_pair(with_b=False)
    h = pair.headers_for('b')
    assert h["X-Token"] == "token_a"

  def test_cookies_for_a(self):
    pair = self._make_pair()
    assert pair.cookies_for('a') == "sess=A"

  def test_cookies_for_b(self):
    pair = self._make_pair()
    assert pair.cookies_for('b') == "sess=B"

  def test_cookies_for_b_fallback(self):
    pair = self._make_pair(with_b=False)
    assert pair.cookies_for('b') == "sess=A"


# ---------------------------------------------------------------------------
# session_from_dict
# ---------------------------------------------------------------------------

class TestSessionFromDict:
  def test_bare_token_sets_authorization(self):
    s = session_from_dict("user", {"token": "eyJabc"})
    assert s.headers.get("Authorization") == "Bearer eyJabc"

  def test_bearer_key_also_works(self):
    s = session_from_dict("user", {"bearer": "eyJxyz"})
    assert s.headers.get("Authorization") == "Bearer eyJxyz"

  def test_cookies_string(self):
    s = session_from_dict("user", {"cookies": "a=1; b=2"})
    assert s.cookies == "a=1; b=2"

  def test_cookies_dict_converted_to_string(self):
    s = session_from_dict("user", {"cookies": {"a": "1", "b": "2"}})
    assert "a=1" in s.cookies
    assert "b=2" in s.cookies

  def test_custom_headers(self):
    s = session_from_dict("user", {"headers": {"X-Org": "acme"}})
    assert s.headers.get("X-Org") == "acme"

  def test_label_set_correctly(self):
    s = session_from_dict("myLabel", {})
    assert s.label == "myLabel"


# ---------------------------------------------------------------------------
# pair_from_config
# ---------------------------------------------------------------------------

class TestPairFromConfig:
  def test_single_session_no_b(self):
    cfg = {"session_a": {"label": "owner", "token": "tok_a"}}
    pair = pair_from_config(cfg)
    assert pair.is_dual is False
    assert pair.session_a.label == "owner"

  def test_dual_session(self):
    cfg = {
      "session_a": {"label": "owner",   "token": "tok_a"},
      "session_b": {"label": "attacker", "token": "tok_b"},
    }
    pair = pair_from_config(cfg)
    assert pair.is_dual is True
    assert pair.session_b is not None
    assert pair.session_b.label == "attacker"

  def test_default_label_a(self):
    pair = pair_from_config({"session_a": {}})
    assert pair.session_a.label == "session_a"
