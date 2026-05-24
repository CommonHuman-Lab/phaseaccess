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