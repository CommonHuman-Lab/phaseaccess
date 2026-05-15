# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/session.py
Session and credential management for multi-role IDOR testing.

A "session" is a named set of credentials (headers + cookies) associated
with a specific role or user.  PhaseAccess supports:

  - Single-session mode  — one set of creds; tests enumeration only
  - Dual-session mode    — session_a owns the resource; session_b should NOT
                           be able to access it.  Cross-session comparison
                           drives CONFIRMED findings.

The SessionPair helper:
  1. Uses session_a to fetch the target, extracting ownership values.
  2. Uses session_b to re-issue the tampered request.
  3. Compares the two responses with the comparator.

"""

from __future__ import annotations

import time
import urllib.request as _req
import urllib.parse as up
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from commonhuman_core.http import random_ua

from .fingerprint import ResponseFingerprint, fingerprint_response, _fetch_fingerprint


# ---------------------------------------------------------------------------
# Session descriptor
# ---------------------------------------------------------------------------

@dataclass
class Session:
  """Named credential set for one role/user."""
  label:    str                           # e.g. "admin", "user_b", "unauthenticated"
  headers:  Dict[str, str] = field(default_factory=dict)
  cookies:  str = ""

  def effective_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = dict(self.headers)
    if extra:
      h.update(extra)
    if self.cookies:
      h.setdefault('Cookie', self.cookies)
    h.setdefault('User-Agent', random_ua())
    return h


# ---------------------------------------------------------------------------
# SessionPair
# ---------------------------------------------------------------------------

@dataclass
class SessionPair:
  """
  Holds session_a (resource owner) and session_b (attacker).
  When session_b is None the tool operates in single-session mode.
  """
  session_a: Session
  session_b: Optional[Session] = None

  @property
  def is_dual(self) -> bool:
    return self.session_b is not None

  def fetch_as_a(
    self,
    url:     str,
    method:  str = "GET",
    body:    str = "",
    proxy:   str = "",
    timeout: int = 15,
  ) -> Optional[ResponseFingerprint]:
    return _fetch_fingerprint(
      url, method,
      self.session_a.effective_headers(),
      body,
      self.session_a.cookies,
      proxy, timeout,
    )

  def fetch_as_b(
    self,
    url:     str,
    method:  str = "GET",
    body:    str = "",
    proxy:   str = "",
    timeout: int = 15,
  ) -> Optional[ResponseFingerprint]:
    if self.session_b is None:
      return None
    return _fetch_fingerprint(
      url, method,
      self.session_b.effective_headers(),
      body,
      self.session_b.cookies,
      proxy, timeout,
    )

  def headers_for(self, which: str) -> Dict[str, str]:
    """Return effective headers for 'a' or 'b'."""
    if which == 'b' and self.session_b:
      return self.session_b.effective_headers()
    return self.session_a.effective_headers()

  def cookies_for(self, which: str) -> str:
    if which == 'b' and self.session_b:
      return self.session_b.cookies
    return self.session_a.cookies


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def session_from_dict(label: str, creds: Dict[str, Any]) -> Session:
  """
  Build a Session from a plain dict.

  Accepted keys:
    headers  — dict of HTTP headers
    cookies  — cookie string  OR  dict (converted to string)
    token    — shortcut: sets Authorization: Bearer <token>
  """
  headers = dict(creds.get('headers') or {})

  # Convenience: bare token
  token = creds.get('token') or creds.get('bearer')
  if token:
    headers['Authorization'] = f"Bearer {token}"

  # cookies: string or dict
  raw_cookies = creds.get('cookies') or ''
  if isinstance(raw_cookies, dict):
    raw_cookies = '; '.join(f"{k}={v}" for k, v in raw_cookies.items())

  return Session(label=label, headers=headers, cookies=str(raw_cookies))


def pair_from_config(config: Dict[str, Any]) -> SessionPair:
  """
  Build a SessionPair from a scan config dict.

  Config structure:
    session_a:
      label:   "owner"
      token:   "eyJ..."
      cookies: "session=abc"
      headers: {"X-Role": "admin"}
    session_b:           # optional
      label:   "attacker"
      cookies: "session=xyz"
  """
  a_cfg = config.get('session_a') or {}
  b_cfg = config.get('session_b')

  label_a = a_cfg.get('label') or 'session_a'
  session_a = session_from_dict(label_a, a_cfg)

  session_b: Optional[Session] = None
  if b_cfg:
    label_b = b_cfg.get('label') or 'session_b'
    session_b = session_from_dict(label_b, b_cfg)

  return SessionPair(session_a=session_a, session_b=session_b)