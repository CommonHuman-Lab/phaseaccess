# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/fingerprint.py
Baseline response fingerprinting for false-positive reduction.

Captures a "fingerprint" of the legitimate (owner's) response so the
comparator can detect meaningful changes rather than reacting to noise
like timestamps, session tokens, or CSRF values.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
import time
import urllib.parse as up
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from commonhuman_core.http import HttpClient

from ._constants import OWNERSHIP_KEYS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Volatile-value patterns — values we strip before structural comparison
# ---------------------------------------------------------------------------

_VOLATILE_PATTERNS = [
  re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),   # ISO timestamps
  re.compile(r'"(updated_at|created_at|timestamp|expires|issued_at|iat|exp)"\s*:\s*\d+'),
  re.compile(r'"(nonce|csrf|_token|xsrf)"\s*:\s*"[^"]+"', re.IGNORECASE),
]

# UUID pattern — kept separate so we can apply it selectively
_RE_UUID_BODY = re.compile(
  r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
  re.IGNORECASE,
)

_VOLATILE_HEADER_KEYS = {
  'date', 'x-request-id', 'x-trace-id', 'x-correlation-id',
  'set-cookie', 'etag', 'last-modified', 'x-runtime', 'x-response-time',
  'cf-ray', 'x-amzn-requestid', 'x-amz-request-id',
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ResponseFingerprint:
  """Fingerprint of a single HTTP response."""
  url:          str
  method:       str
  status:       int
  body:         str
  headers:      Dict[str, str]

  # Derived fields
  content_type: str = ""
  body_length:  int = 0

  # Stable body hash (volatile values stripped)
  stable_hash:  str = ""

  # Top-level JSON keys present (if JSON response)
  json_keys:    List[str] = field(default_factory=list)

  # Ownership fields found in body (email, user_id, etc.)
  ownership_values: Dict[str, str] = field(default_factory=dict)

  # Structural signature: sorted list of non-volatile top-level JSON keys + types
  structure_sig: str = ""

  # Elapsed time (ms) — useful for timing-based IDOR
  elapsed_ms:   float = 0.0

  def to_dict(self) -> Dict[str, Any]:
    return {
      "url":         self.url,
      "method":      self.method,
      "status":      self.status,
      "body_length": self.body_length,
      "content_type": self.content_type,
      "stable_hash": self.stable_hash,
      "json_keys":   self.json_keys,
      "ownership_values": self.ownership_values,
      "structure_sig": self.structure_sig,
      "elapsed_ms":  self.elapsed_ms,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fingerprint_response(
  url:           str,
  method:        str,
  status:        int,
  body:          str,
  headers:       Dict[str, str],
  elapsed_ms:    float = 0.0,
  baseline_body: Optional[str] = None,
) -> ResponseFingerprint:
  """
  Build a ResponseFingerprint from a raw HTTP response.
  Called after every request — both baseline and tampered.

  `baseline_body` — when provided (tampered requests), UUIDs that were
  already present in the baseline are treated as volatile and stripped
  from the stable hash.  UUIDs that are NEW in the tampered response
  (potential cross-user IDs) are preserved in the hash, making them
  detectable as a meaningful difference.
  """
  content_type = _get_header(headers, 'content-type', '')
  stable       = _stabilise(body, baseline_body=baseline_body)
  stable_hash  = hashlib.sha256(stable.encode()).hexdigest()[:16]
  json_keys, ownership, structure_sig = _analyse_json(body, content_type)

  # Supplement with regex-extracted PII when key-based extraction found nothing.
  # Runs for any content type — JSON APIs that lack recognised key names (e.g.
  # vendor-prefixed "x-user-email") still expose email addresses as literal
  # strings that the regex can catch.
  if not ownership:
    ownership = _extract_html_ownership(body)

  return ResponseFingerprint(
    url=url,
    method=method,
    status=status,
    body=body,
    headers={k.lower(): v for k, v in headers.items()
             if k.lower() not in _VOLATILE_HEADER_KEYS},
    content_type=content_type,
    body_length=len(body),
    stable_hash=stable_hash,
    json_keys=json_keys,
    ownership_values=ownership,
    structure_sig=structure_sig,
    elapsed_ms=elapsed_ms,
  )


def build_baseline(
  url:         str,
  method:      str      = "GET",
  headers:     Optional[Dict[str, str]] = None,
  body:        str      = "",
  cookies:     str      = "",
  proxy:       str      = "",
  timeout:     int      = 15,
  repeats:     int      = 2,
  verify_ssl:  bool     = True,
  delay:       float    = 0.0,
) -> Optional[ResponseFingerprint]:
  """
  Fetch the URL `repeats` times with the *owner's* credentials and return
  the most stable fingerprint.  Two fetches lets us detect volatile fields
  (values that differ between fetches) so we don't false-positive on them.

  Returns None on network failure.
  """
  fps: List[ResponseFingerprint] = []
  for _ in range(repeats):
    fp = _fetch_fingerprint(
      url, method, headers or {}, body, cookies, proxy, timeout,
      verify_ssl=verify_ssl,
    )
    if fp:
      fps.append(fp)
    if delay > 0:
      _sleep(delay)

  if not fps:
    logger.debug("Baseline fetch skipped/failed for %s", url)
    return None

  # If we have two fetches, identify JSON field values that changed between
  # them (truly volatile) and bake those volatile values into the first
  # fingerprint's stable_hash so tampered responses won't be compared against
  # them.
  if len(fps) >= 2:
    volatile_vals = _detect_volatile_values(fps[0].body, fps[1].body)
    if volatile_vals:
      fps[0] = _rebuild_with_extra_volatiles(fps[0], volatile_vals)

  return fps[0]


def _detect_volatile_values(body1: str, body2: str) -> List[str]:
  """
  Compare two JSON response bodies and return scalar values that differ
  between them (per key).  These are runtime-volatile values (timestamps,
  nonces, session tokens embedded in body, etc.) that should be ignored
  when comparing a tampered response against the baseline.
  """
  volatile: List[str] = []
  for body in (body1, body2):
    if not body.strip().startswith(('{', '[')):
      return volatile
  try:
    obj1 = json.loads(body1)
    obj2 = json.loads(body2)
  except json.JSONDecodeError:
    return volatile

  def _collect(o1: Any, o2: Any) -> None:
    if isinstance(o1, dict) and isinstance(o2, dict):
      for k in o1:
        if k in o2:
          _collect(o1[k], o2[k])
    elif isinstance(o1, list) and isinstance(o2, list):
      for a, b in zip(o1[:10], o2[:10]):
        _collect(a, b)
    elif o1 != o2:
      # Scalar values that differ between the two fetches are volatile
      for v in (o1, o2):
        s = str(v)
        # Only add if meaningful length; short values like "1"/"2" are noise
        if len(s) >= 6:
          volatile.append(s)

  _collect(obj1, obj2)
  return volatile


def _rebuild_with_extra_volatiles(
  fp: "ResponseFingerprint",
  volatile_vals: List[str],
) -> "ResponseFingerprint":
  """
  Re-compute the stable_hash of `fp` after stripping `volatile_vals`
  from the body.  Returns a new ResponseFingerprint with the updated hash.
  """
  body = fp.body
  for val in volatile_vals:
    body = body.replace(val, '__VOLATILE__')
  # Also apply the standard stabilise pass (already applied, but idempotent)
  stable = _stabilise(body, baseline_body=None)
  new_hash = hashlib.sha256(stable.encode()).hexdigest()[:16]
  return dataclasses.replace(fp, stable_hash=new_hash)


def _fetch_fingerprint(
    url:        str,
    method:     str,
    headers:    Dict[str, str],
    body:       str,
    cookies:    str,
    proxy:      str,
    timeout:    int,
    verify_ssl: bool = True,
) -> Optional[ResponseFingerprint]:
    """Make a single HTTP request and return a fingerprint."""
    req_headers = dict(headers)
    if cookies:
        req_headers.setdefault("Cookie", cookies)
    req_headers.setdefault("User-Agent", "PhaseAccess/1.0")

    client = HttpClient(
        timeout=timeout,
        proxy=proxy,
        headers=req_headers,
        verify_ssl=verify_ssl,
        delay=0.0,
    )
    body_bytes = body.encode() if body else None

    t0 = time.time()
    try:
        resp = client._session.request(
            method, url, data=body_bytes, timeout=timeout, stream=True
        )
    except Exception as exc:
        logger.warning("Network error fetching %s: %s", url, exc)
        return None

    elapsed_ms = (time.time() - t0) * 1000
    ct = resp.headers.get("Content-Type", "")
    if "event-stream" in ct:
        logger.debug("Skipping streaming endpoint %s", url)
        resp.close()
        return None
    try:
        body_bytes_raw = resp.raw.read(524288, decode_content=True)
        body = body_bytes_raw.decode(resp.encoding or "utf-8", errors="replace")
    except Exception:
        body = ""
    finally:
        resp.close()

    return fingerprint_response(
        url=url,
        method=method,
        status=resp.status_code,
        body=body,
        headers=dict(resp.headers),
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sleep(seconds: float) -> None:
  if seconds > 0:
    time.sleep(seconds)


def _stabilise(body: str, baseline_body: Optional[str] = None) -> str:
  """
  Strip volatile values from body before hashing.

  If `baseline_body` is provided, only UUIDs that appeared in the
  baseline are stripped (they are known-stable noise).  New UUIDs in
  the tampered response are preserved so the comparator can detect them
  as evidence of cross-user data leakage.

  Without `baseline_body` (i.e. when fingerprinting the baseline itself)
  all UUIDs are stripped so the baseline hash is UUID-agnostic for the
  purposes of non-UUID field comparison.
  """
  for pat in _VOLATILE_PATTERNS:
    body = pat.sub('__VOLATILE__', body)

  if baseline_body is None:
    # Baseline: strip all UUIDs
    body = _RE_UUID_BODY.sub('__VOLATILE__', body)
  else:
    # Tampered: strip only UUIDs that were in the baseline
    baseline_uuids = set(_RE_UUID_BODY.findall(baseline_body))
    for uid in baseline_uuids:
      body = body.replace(uid, '__VOLATILE__')
      body = body.replace(uid.lower(), '__VOLATILE__')
      body = body.replace(uid.upper(), '__VOLATILE__')

  return body


def _get_header(headers: Dict[str, str], key: str, default: str = "") -> str:
  for k, v in headers.items():
    if k.lower() == key.lower():
      return v
  return default


_EMAIL_RE = re.compile(r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b')
_SSN_RE   = re.compile(r'\b(\d{3}-\d{2}-\d{4})\b')
_INS_RE   = re.compile(r'\b([A-Z]{2,}-\d{4,})\b')
# Require separators (-, ., space, or parens) so we don't match plain integers
# like trading volumes that happen to be 10 digits long.
_PHONE_RE = re.compile(
  r'\b(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4})\b'
)

# Greeting patterns — "Welcome back, Alice Porter" / "Good morning, dr.carter"
# Handles both proper-name greetings and lowercase username greetings.
_GREETING_RE = re.compile(
  r'(?:Welcome\s+back|Welcome|Hello|Greetings|Hi|Good\s+morning|Good\s+afternoon|Good\s+evening)'
  r'\b[^A-Za-z]{0,3}'
  r'([A-Za-z][A-Za-z0-9_.]{2,49}(?:\s+[A-Z][a-zA-Z]+)*)',
)

# <a href="/profile/2">alice.p</a> — profile link anchor text as username signal.
# Covers common user-ownership URL prefixes across many apps.
_PROFILE_ANCHOR_RE = re.compile(
  r'<a\b[^>]*\bhref=["\'][^"\']*/'
  r'(?:profile|user|users|member|members|player|players|patient|patients|'
  r'accounts?|admin/users?|admin/staff|suite|staff|customer|customers)/\d+[^"\']*["\'][^>]*>'
  r'([A-Za-z0-9][^<]{2,49})</a>',
  re.IGNORECASE | re.DOTALL,
)

# <h1>TRADER — alice.p</h1> — entity-type heading with username
_HEADING_USER_RE = re.compile(
  r'<(?:h[1-3]|title)\b[^>]*>[^<]*?'
  r'(?:TRADER|USER|PATIENT|MEMBER|CUSTOMER|PLAYER|STAFF|ACCOUNT|SUBSCRIBER)\s*'
  r'[—–\-]+\s*([A-Za-z0-9][A-Za-z0-9_.@+\-]{3,49})',
  re.IGNORECASE,
)

# <h1>lucky_larry's Transactions</h1> — possessive username in headings.
# The "owner" identifier is the token immediately before 's.
# Require at least one non-alpha character (dot/underscore/digit) or a digit
# suffix to avoid matching common English possessives like "Today's".
_POSSESSIVE_HEADING_RE = re.compile(
  r"<h[1-3][^>]*>([A-Za-z][A-Za-z0-9_.]{2,39})'s\s+\w",
  re.IGNORECASE,
)

_GENERIC_LINK_TEXT = frozenset({
  'profile', 'edit profile', 'view profile', 'my profile', 'user profile',
  'settings', 'account', 'details', 'edit', 'view', 'click here', 'admin',
  'dashboard', 'back', 'home', 'update', 'manage', 'delete',
})

# <strong>dr.carter</strong> — bolded username in message/activity context.
_STRONG_USERNAME_RE = re.compile(
  r'<strong\b[^>]*>([A-Za-z][A-Za-z0-9_.]{2,39})</strong>',
  re.IGNORECASE,
)

# Supplementary: links to /profile (no numeric ID) whose text looks like a
# username — <a href="/profile">alice.wang</a>.  Must contain a dot, underscore,
# or digit so we don't capture English words ("Read", "More", etc.).
_PROFILE_NOID_RE = re.compile(
  r'<a\b[^>]*href=["\'][^"\']*/'
  r'(?:profile|account|member|user|staff|patient)/?["\'][^>]*>'
  r'([A-Za-z][A-Za-z0-9_.\-]{2,39})</a>',
  re.IGNORECASE,
)


def _extract_html_ownership(body: str) -> Dict[str, str]:
  """
  Regex-scan an HTML body for ownership markers: PII (emails, SSNs, insurance
  IDs, phone numbers) and structural signals (greeting names, profile link text,
  entity-type headings).  Returns one value per category — enough to confirm
  cross-user leakage when these values differ between baseline and tampered.
  """
  result: Dict[str, str] = {}

  m = _EMAIL_RE.search(body)
  if m:
    result['email'] = m.group(1)
  m = _SSN_RE.search(body)
  if m:
    result['ssn'] = m.group(1)
  m = _INS_RE.search(body)
  if m:
    result['insurance_id'] = m.group(1)
  m = _PHONE_RE.search(body)
  if m:
    result['phone'] = m.group(1).strip()

  # Greeting name: "Welcome back, Alice Porter"
  m = _GREETING_RE.search(body)
  if m:
    name = m.group(1).strip()
    if len(name) >= 6:
      result['greeting_name'] = name

  # Profile link anchor text — collect first and second distinct profile link texts.
  # The first match is usually the nav bar showing the CURRENT user's display name
  # (ambient session signal → profile_username).  A second DISTINCT match is
  # typically the resource OWNER's username in the page content (resource-specific
  # signal → profile_owner).  Both are checked in the cross-session analysis.
  _seen_profile_texts: list = []
  # Primary: links that include a numeric user ID (e.g. /profile/2, /admin/users/3)
  for m in _PROFILE_ANCHOR_RE.finditer(body):
    text = m.group(1).strip()
    text_lc = text.lower()
    if (len(text) >= 4
        and text_lc not in _GENERIC_LINK_TEXT
        and not any(t.lower() == text_lc for t in _seen_profile_texts)):
      _seen_profile_texts.append(text)
      if len(_seen_profile_texts) >= 2:
        break
  # Fallback: links to /profile (no ID) whose text looks like a username
  # (contains dot/underscore/digit).  Captures <a href="/profile">alice.wang</a>
  # in apps that use the current user's profile path without an explicit ID.
  if not _seen_profile_texts:
    for m in _PROFILE_NOID_RE.finditer(body):
      text = m.group(1).strip()
      text_lc = text.lower()
      if (len(text) >= 4
          and text_lc not in _GENERIC_LINK_TEXT
          and re.search(r'[._\d]', text)
          and not any(t.lower() == text_lc for t in _seen_profile_texts)):
        _seen_profile_texts.append(text)
        if len(_seen_profile_texts) >= 2:
          break
  if _seen_profile_texts:
    result['profile_username'] = _seen_profile_texts[0]
  if len(_seen_profile_texts) >= 2:
    result['profile_owner'] = _seen_profile_texts[1]

  # Heading username: <h1>TRADER — alice.p</h1>
  m = _HEADING_USER_RE.search(body)
  if m:
    text = m.group(1).strip()
    if len(text) >= 4:
      result['heading_username'] = text

  # Possessive heading username: <h1>lucky_larry's Transactions</h1>
  # Only capture if the token looks like a username (contains dot/underscore/digit),
  # not a common English possessive like "Today" or "Player".
  if 'possessive_name' not in result:
    m = _POSSESSIVE_HEADING_RE.search(body)
    if m:
      text = m.group(1).strip()
      if (len(text) >= 4 and
          (re.search(r'[._\d]', text) or text[0].islower())):
        result['possessive_name'] = text

  # <strong>dr.carter</strong> — bolded username in message sender/activity context.
  # Only capture if text looks like a username (has dot/underscore/digit).
  if 'strong_username' not in result:
    for m in _STRONG_USERNAME_RE.finditer(body):
      text = m.group(1).strip()
      # Require a dot or underscore — prevents hex hashes and pure-digit values
      # from being captured (they pass the digit check but aren't usernames).
      if (len(text) >= 4
          and re.search(r'[._]', text)
          and text.lower() not in _GENERIC_LINK_TEXT):
        result['strong_username'] = text
        break

  return result


def _analyse_json(
  body: str,
  content_type: str,
) -> Tuple[List[str], Dict[str, str], str]:
  """
  Parse JSON body.
  Returns: (top_level_keys, ownership_fields_found, structure_signature)
  """
  keys: List[str] = []
  ownership: Dict[str, str] = {}
  sig = ""

  if 'json' not in content_type and not body.strip().startswith(('{', '[')):
    return keys, ownership, sig

  try:
    parsed = json.loads(body)
  except json.JSONDecodeError as exc:
    logger.debug("JSON parse error in response body: %s", exc)
    return keys, ownership, sig

  if isinstance(parsed, dict):
    keys = sorted(parsed.keys())
    sig  = _structure_sig(parsed)
    # Recursively find ownership values
    _extract_ownership(parsed, ownership, depth=0)
  elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
    keys = sorted(parsed[0].keys())
    sig  = f"list[{_structure_sig(parsed[0])}]"
    for item in parsed[:5]:
      _extract_ownership(item, ownership, depth=0)

  return keys, ownership, sig


def _structure_sig(obj: Any, depth: int = 0) -> str:
  """Produce a stable type-structure signature for a JSON object."""
  if depth > 3 or not isinstance(obj, dict):
    return type(obj).__name__
  parts = []
  for k in sorted(obj.keys()):
    v = obj[k]
    if isinstance(v, dict):
      parts.append(f"{k}:obj")
    elif isinstance(v, list):
      parts.append(f"{k}:arr")
    elif isinstance(v, bool):
      parts.append(f"{k}:bool")
    elif isinstance(v, int):
      parts.append(f"{k}:int")
    elif isinstance(v, float):
      parts.append(f"{k}:float")
    else:
      parts.append(f"{k}:str")
  return "{" + ",".join(parts) + "}"


def _extract_ownership(
  obj: Any,
  out: Dict[str, str],
  depth: int,
) -> None:
  """Walk obj recursively and collect ownership field values."""
  if depth > 4 or not isinstance(obj, dict):
    return
  for k, v in obj.items():
    if k.lower() in {ow.lower() for ow in OWNERSHIP_KEYS}:
      if v is not None and str(v) not in ('', 'null', 'None'):
        out[k] = str(v)
    elif isinstance(v, dict):
      _extract_ownership(v, out, depth + 1)
    elif isinstance(v, list):
      for item in v[:3]:
        _extract_ownership(item, out, depth + 1)