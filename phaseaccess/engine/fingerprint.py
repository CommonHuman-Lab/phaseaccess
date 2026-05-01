"""
PhaseAccess — engine/fingerprint.py
Baseline response fingerprinting for false-positive reduction.

Captures a "fingerprint" of the legitimate (owner's) response so the
comparator can detect meaningful changes rather than reacting to noise
like timestamps, session tokens, or CSRF values.

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.request as _req
import urllib.parse as up
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ._constants import OWNERSHIP_KEYS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Volatile-value patterns — values we strip before structural comparison
# ---------------------------------------------------------------------------

_VOLATILE_PATTERNS = [
  re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),   # ISO timestamps
  re.compile(r'"(updated_at|created_at|timestamp|expires|issued_at|iat|exp)"\s*:\s*\d+'),
  re.compile(r'"(nonce|csrf|_token|xsrf)"\s*:\s*"[^"]+"', re.IGNORECASE),
  re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
             re.IGNORECASE),  # UUIDs in body
]

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
  url:        str,
  method:     str,
  status:     int,
  body:       str,
  headers:    Dict[str, str],
  elapsed_ms: float = 0.0,
) -> ResponseFingerprint:
  """
  Build a ResponseFingerprint from a raw HTTP response.
  Called after every request — both baseline and tampered.
  """
  content_type = _get_header(headers, 'content-type', '')
  stable       = _stabilise(body)
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
  the most stable fingerprint.  Two fetches lets us flag volatile fields.

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
    _sleep(delay if delay > 0 else 0.1)

  if not fps:
    logger.warning("Baseline fetch failed for %s", url)
    return None

  # Return the first; caller uses comparator to diff against tampered responses
  return fps[0]


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
    req_headers.setdefault('Cookie', cookies)
  req_headers.setdefault('User-Agent', 'PhaseAccess/1.0')

  body_bytes = body.encode() if body else None

  request = _req.Request(
    url,
    data=body_bytes,
    headers=req_headers,
    method=method,
  )

  handler_chain: list = []
  if proxy:
    proxy_handler = _req.ProxyHandler({
      'http':  proxy,
      'https': proxy,
    })
    handler_chain.append(proxy_handler)
  if not verify_ssl:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    handler_chain.append(_req.HTTPSHandler(context=ssl_ctx))
  handler_chain.append(_req.HTTPCookieProcessor())

  opener = _req.build_opener(*handler_chain)

  t0 = time.time()
  try:
    with opener.open(request, timeout=timeout) as resp:
      elapsed_ms = (time.time() - t0) * 1000
      resp_body  = resp.read().decode('utf-8', errors='replace')
      resp_headers: Dict[str, str] = dict(resp.headers)
      status = resp.status

    return fingerprint_response(
      url=url,
      method=method,
      status=status,
      body=resp_body,
      headers=resp_headers,
      elapsed_ms=elapsed_ms,
    )

  except urllib.error.HTTPError as exc:
    # HTTP errors (4xx/5xx) are still valid fingerprint-able responses
    try:
      elapsed_ms = (time.time() - t0) * 1000
      resp_body  = exc.read().decode('utf-8', errors='replace')
      resp_headers = dict(exc.headers)
      return fingerprint_response(
        url=url,
        method=method,
        status=exc.code,
        body=resp_body,
        headers=resp_headers,
        elapsed_ms=elapsed_ms,
      )
    except Exception as inner:
      logger.debug("Failed to read HTTPError body for %s: %s", url, inner)
      return None
  except urllib.error.URLError as exc:
    logger.warning("Network error fetching %s: %s", url, exc.reason)
    return None
  except ssl.SSLError as exc:
    logger.warning(
      "SSL error fetching %s: %s  (use --insecure to skip verification)", url, exc
    )
    return None
  except Exception as exc:
    logger.debug("Unexpected error fetching %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sleep(seconds: float) -> None:
  if seconds > 0:
    time.sleep(seconds)


def _stabilise(body: str) -> str:
  """Strip volatile values from body before hashing."""
  for pat in _VOLATILE_PATTERNS:
    body = pat.sub('__VOLATILE__', body)
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
