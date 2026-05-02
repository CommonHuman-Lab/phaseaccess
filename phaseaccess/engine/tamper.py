# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/tamper.py
HTTP request replayer: substitutes tampered ID values and fires the request,
returning a ResponseFingerprint for comparison.

Handles all IDORLocation types:
  - QUERY_PARAM    — replace ?param=original → ?param=tampered
  - PATH_SEGMENT   — replace /path[N]/original → /path[N]/tampered
  - POST_BODY      — form-encoded or JSON body field
  - JSON_BODY      — nested JSON field (dotted path)
  - HEADER         — custom header value
  - COOKIE         — cookie string value
  - JWT_CLAIM      — replace a JWT in headers/cookies/query/body

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import copy
import json
import logging
import time
import urllib.error
import urllib.parse as up
import urllib.request as _req
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .reporter import IDORLocation
from .extractor import ObjectRef
from .fingerprint import ResponseFingerprint, fingerprint_response
from .http_client import get_opener

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result of a single tampered request
# ---------------------------------------------------------------------------

@dataclass
class TamperResult:
  ref:              ObjectRef         # original object reference
  tampered_value:   str               # what we substituted
  description:      str               # human-readable why
  fingerprint:      ResponseFingerprint
  # Effective request details (for curl reproduction)
  effective_url:    str = ""
  effective_headers: Optional[Dict[str, str]] = field(default=None)
  effective_body:   str = ""

  def __post_init__(self) -> None:
    if self.effective_headers is None:
      self.effective_headers = {}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def send_tampered(
  ref:            ObjectRef,
  tampered_value: str,
  description:    str,
  extra_headers:  Optional[Dict[str, str]] = None,
  cookies:        str = "",
  proxy:          str = "",
  timeout:        int = 15,
  verify_ssl:     bool = True,
  delay:          float = 0.0,
  baseline_body:  Optional[str] = None,
) -> Optional[TamperResult]:
  """
  Re-issue `ref.url` with `tampered_value` substituted for `ref.value`
  at `ref.location`.  Returns a TamperResult or None on network failure.
  """
  try:
    url, headers, body = _build_request(ref, tampered_value, extra_headers or {}, cookies)
  except Exception as exc:
    logger.debug(
      "Failed to build tampered request for %s param=%s value=%r: %s",
      ref.url, ref.param, tampered_value, exc,
    )
    return None

  if delay > 0:
    time.sleep(delay)

  fp = fire_request(url, ref.method, headers, body, proxy, timeout,
                   verify_ssl=verify_ssl, baseline_body=baseline_body)
  if fp is None:
    return None

  return TamperResult(
    ref=ref,
    tampered_value=tampered_value,
    description=description,
    fingerprint=fp,
    effective_url=url,
    effective_headers=headers,
    effective_body=body,
  )


def send_method_variants(
  ref:            ObjectRef,
  extra_headers:  Optional[Dict[str, str]] = None,
  cookies:        str = "",
  proxy:          str = "",
  timeout:        int = 15,
  verify_ssl:     bool = True,
  delay:          float = 0.0,
) -> List[TamperResult]:
  """
  Try alternative HTTP methods on the same endpoint with the *original* value.
  Used to detect method-bypass IDOR (e.g. GET is protected but DELETE is not).
  """
  results: List[TamperResult] = []
  for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
    if method == ref.method:
      continue
    variant_ref = ObjectRef(
      location=ref.location,
      param=ref.param,
      value=ref.value,
      id_type=ref.id_type,
      url=ref.url,
      method=method,
      body_context=ref.body_context,
      header_name=ref.header_name,
    )
    if delay > 0:
      time.sleep(delay)
    fp = fire_request(
      ref.url, method, dict(extra_headers or {}), "", proxy, timeout,
      verify_ssl=verify_ssl,
    )
    if fp:
      results.append(TamperResult(
        ref=variant_ref,
        tampered_value=ref.value,
        description=f"method bypass: {method}",
        fingerprint=fp,
      ))
  return results


def send_param_pollution(
  ref:            ObjectRef,
  tampered_value: str,
  extra_headers:  Optional[Dict[str, str]] = None,
  cookies:        str = "",
  proxy:          str = "",
  timeout:        int = 15,
  verify_ssl:     bool = True,
  delay:          float = 0.0,
) -> Optional[TamperResult]:
  """
  Duplicate a query param — ?id=own&id=victim — to detect server-side
  last-wins or first-wins behaviour.
  """
  if ref.location != IDORLocation.QUERY_PARAM:
    return None

  parsed = up.urlparse(ref.url)
  qs_pairs = up.parse_qsl(parsed.query, keep_blank_values=True)
  # Append duplicate
  qs_pairs.append((ref.param, tampered_value))
  new_url = up.urlunparse(parsed._replace(query=up.urlencode(qs_pairs)))

  if delay > 0:
    time.sleep(delay)
  fp = fire_request(new_url, ref.method, dict(extra_headers or {}), "", proxy, timeout,
                   verify_ssl=verify_ssl)
  if fp is None:
    return None

  return TamperResult(
    ref=ref,
    tampered_value=tampered_value,
    description=f"param pollution: {ref.param}=[own,{tampered_value}]",
    fingerprint=fp,
  )


# ---------------------------------------------------------------------------
# Request builder
# ---------------------------------------------------------------------------

def _build_request(
  ref:           ObjectRef,
  tampered:      str,
  extra_headers: Dict[str, str],
  cookies:       str,
) -> tuple[str, Dict[str, str], str]:
  """Returns (url, headers_dict, body_str)."""

  url     = ref.url
  headers = dict(extra_headers)
  body    = ""

  headers.setdefault('User-Agent', 'PhaseAccess/1.0')
  if cookies:
    headers.setdefault('Cookie', cookies)

  loc = ref.location

  if loc == IDORLocation.QUERY_PARAM:
    url = _replace_query_param(url, ref.param, tampered)

  elif loc == IDORLocation.PATH_SEGMENT:
    url = _replace_path_segment(url, ref.param, ref.value, tampered)

  elif loc == IDORLocation.POST_BODY:
    # Form-encoded body — start from the original raw body to preserve all fields
    original_raw = ref.body_context if isinstance(ref.body_context, str) else ""
    parsed_body = up.parse_qs(original_raw, keep_blank_values=True)
    parsed_body[ref.param] = [tampered]
    body = up.urlencode(
      {k: v[0] for k, v in parsed_body.items()},
      quote_via=up.quote,
    )
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

  elif loc == IDORLocation.JSON_BODY:
    ctx = copy.deepcopy(ref.body_context) if isinstance(ref.body_context, dict) else {}
    _set_nested(ctx, ref.param, tampered)
    body = json.dumps(ctx)
    headers['Content-Type'] = 'application/json'

  elif loc == IDORLocation.HEADER:
    headers[ref.header_name or ref.param] = tampered

  elif loc == IDORLocation.COOKIE:
    headers['Cookie'] = _replace_cookie(
      headers.get('Cookie', cookies), ref.param, tampered
    )

  elif loc == IDORLocation.JWT_CLAIM:
    # JWT is typically in Authorization header or cookie
    auth = headers.get('Authorization', '')
    if auth.lower().startswith('bearer '):
      headers['Authorization'] = f"Bearer {tampered}"
    else:
      # Fall back to query param if no auth header
      url = _replace_query_param(url, ref.param, tampered)

  return url, headers, body


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

def fire_request(
  url:           str,
  method:        str,
  headers:       Dict[str, str],
  body:          str,
  proxy:         str,
  timeout:       int,
  verify_ssl:    bool = True,
  _retries:      int = 2,
  baseline_body: Optional[str] = None,
) -> Optional[ResponseFingerprint]:
  body_bytes = body.encode() if body else None
  req = _req.Request(url, data=body_bytes, headers=headers, method=method)
  opener = get_opener(proxy, verify_ssl)

  for attempt in range(1 + _retries):
    t0 = time.time()
    try:
      with opener.open(req, timeout=timeout) as resp:
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
        baseline_body=baseline_body,
      )

    except urllib.error.HTTPError as exc:
      # Rate-limited — back off and retry
      if exc.code == 429 and attempt < _retries:
        retry_after = int(exc.headers.get('Retry-After', '2'))
        logger.debug("Rate limited on %s — backing off %ds", url, retry_after)
        time.sleep(min(retry_after, 30))
        continue
      # All other HTTP errors: still a valid fingerprint-able response
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
          baseline_body=baseline_body,
        )
      except Exception as inner:
        logger.debug("Failed to read HTTPError body for %s: %s", url, inner)
        return None

    except urllib.error.URLError as exc:
      logger.debug("Network error on tampered request %s: %s", url, exc.reason)
      return None
    except ssl.SSLError as exc:
      logger.debug("SSL error on tampered request %s: %s", url, exc)
      return None
    except Exception as exc:
      logger.debug("Unexpected error on tampered request %s: %s", url, exc)
      return None

  return None  # exhausted retries


# ---------------------------------------------------------------------------
# URL / body mutation helpers
# ---------------------------------------------------------------------------

def _replace_query_param(url: str, param: str, new_value: str) -> str:
  parsed = up.urlparse(url)
  qs = up.parse_qsl(parsed.query, keep_blank_values=True)
  replaced = False
  new_qs = []
  for k, v in qs:
    if k == param and not replaced:
      new_qs.append((k, new_value))
      replaced = True
    else:
      new_qs.append((k, v))
  if not replaced:
    new_qs.append((param, new_value))
  return up.urlunparse(parsed._replace(query=up.urlencode(new_qs)))


def _replace_path_segment(url: str, param: str, original: str, new_value: str) -> str:
  """param is 'path[N]'; replace the Nth non-empty segment."""
  parsed   = up.urlparse(url)
  segments = parsed.path.split('/')

  # Extract index from "path[N]"
  try:
    idx_str = param.split('[')[1].rstrip(']')
    idx     = int(idx_str)
  except (IndexError, ValueError):
    # Fallback: replace first occurrence of original in path
    new_path = parsed.path.replace(
      '/' + original + '/', '/' + new_value + '/', 1
    )
    return up.urlunparse(parsed._replace(path=new_path))

  # segments includes leading '' from leading '/'
  non_empty = [i for i, s in enumerate(segments) if s]
  if idx < len(non_empty):
    segments[non_empty[idx]] = new_value
  return up.urlunparse(parsed._replace(path='/'.join(segments)))


def _replace_cookie(cookie_str: str, name: str, new_value: str) -> str:
  """Replace name=value in a cookie string."""
  pairs = [p.strip() for p in cookie_str.split(';')]
  new_pairs = []
  replaced = False
  for pair in pairs:
    if '=' in pair:
      k, _, v = pair.partition('=')
      if k.strip() == name and not replaced:
        new_pairs.append(f"{k}={new_value}")
        replaced = True
      else:
        new_pairs.append(pair)
    else:
      new_pairs.append(pair)
  if not replaced:
    new_pairs.append(f"{name}={new_value}")
  return '; '.join(p for p in new_pairs if p)


def _set_nested(obj: Dict[str, Any], dotted_key: str, value: Any) -> None:
  """Set obj[a][b][c] = value given dotted_key='a.b.c'."""
  keys = dotted_key.split('.')
  cur  = obj
  for k in keys[:-1]:
    # Handle array notation "items[0]" → key="items", index=0
    if '[' in k:
      base, _, rest = k.partition('[')
      try:
        i = int(rest.rstrip(']'))
        sub = cur.get(base)
        if isinstance(sub, list) and i < len(sub):
          cur = sub[i]
          continue
      except (ValueError, TypeError):
        pass
      k = base
    cur = cur.setdefault(k, {})
  last = keys[-1]
  if '[' in last:
    base, _, rest = last.partition('[')
    try:
      i   = int(rest.rstrip(']'))
      sub = cur.get(base)
      if isinstance(sub, list) and i < len(sub):
        sub[i] = value
        return
    except (ValueError, TypeError):
      pass
    last = base
  cur[last] = value