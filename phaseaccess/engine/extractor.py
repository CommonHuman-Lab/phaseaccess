# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/extractor.py
Object reference extraction from URLs, request bodies, response bodies, and headers.

Finds every parameter that looks like an object reference — across:
  - URL query string params
  - URL path segments
  - POST/PUT body (form-encoded and JSON)
  - HTTP headers (custom + standard)
  - JSON response bodies (for ID harvesting / chaining)

Returns structured ObjectRef instances ready for tamper.py to act on.

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse as up
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .reporter import IDORLocation, IDType
from .id_engine import detect_id_type
from ._constants import OWNERSHIP_KEYS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Keyword heuristics — parameter names that likely carry object references
# ---------------------------------------------------------------------------

_ID_PARAM_KEYWORDS = {
  # Generic IDs
  'id', 'ids', 'uid', 'uuid', 'guid',
  # Entity-prefixed IDs
  'user_id', 'userid', 'userId',
  'account_id', 'accountid', 'accountId',
  'order_id', 'orderid', 'orderId',
  'invoice_id', 'invoiceid',
  'document_id', 'doc_id', 'docid',
  'file_id', 'fileid',
  'post_id', 'postid',
  'comment_id', 'commentid',
  'message_id', 'messageid',
  'record_id', 'recordid',
  'object_id', 'objectid',
  'item_id', 'itemid',
  'product_id', 'productid',
  'customer_id', 'customerid', 'customerId',
  'project_id', 'projectid',
  'ticket_id', 'ticketid',
  'report_id', 'reportid',
  'resource_id', 'resourceid',
  'ref', 'reference', 'key', 'token',
  'pid', 'rid', 'eid', 'cid',
  # Suffixes matched by regex below
}

# Also match anything that ends in _id, Id, -id, [id]
_ID_SUFFIX_RE = re.compile(
  r'(?:^|[_\-\[])(id|uid|guid|uuid|ref|key|num|no|code|token)$',
  re.IGNORECASE,
)

# Headers that may carry object references
_ID_HEADERS = {
  'x-user-id', 'x-userid', 'x-account-id', 'x-accountid',
  'x-tenant-id', 'x-tenantid', 'x-organization-id', 'x-org-id',
  'x-resource-id', 'x-object-id', 'x-customer-id',
  'x-forwarded-user', 'x-authenticated-userid',
  'x-subject', 'x-actor',
}

# JSON response keys that indicate object ownership
_OWNERSHIP_KEYS = OWNERSHIP_KEYS


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ObjectRef:
  """A single object reference found in a request or response."""
  location:   IDORLocation
  param:      str               # parameter name or "path[N]" for path segments
  value:      str
  id_type:    IDType
  url:        str
  method:     str               # HTTP method this applies to
  # For JSON bodies — the full body dict (needed to replay the request)
  # For POST_BODY (form-encoded) — the raw body string (all fields preserved)
  body_context: Optional[Any] = None
  # For headers
  header_name: Optional[str] = None


@dataclass
class HarvestedID:
  """An ID found in a response body belonging to a (possibly different) user."""
  field:  str
  value:  str
  url:    str       # where it was found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_from_url(url: str, method: str = "GET") -> List[ObjectRef]:
  """Extract object references from URL query parameters and path segments."""
  refs: List[ObjectRef] = []

  parsed = up.urlparse(url)

  # Query string params
  qs = up.parse_qs(parsed.query, keep_blank_values=True)
  for name, values in qs.items():
    value = values[0] if values else ""
    if _is_id_param(name) or _looks_like_id(value):
      refs.append(ObjectRef(
        location=IDORLocation.QUERY_PARAM,
        param=name,
        value=value,
        id_type=detect_id_type(value),
        url=url,
        method=method,
      ))

  # Path segments
  segments = [s for s in parsed.path.split('/') if s]
  for i, seg in enumerate(segments):
    if _looks_like_id(seg):
      refs.append(ObjectRef(
        location=IDORLocation.PATH_SEGMENT,
        param=f"path[{i}]",
        value=seg,
        id_type=detect_id_type(seg),
        url=url,
        method=method,
      ))

  return refs


def extract_from_body(url: str, method: str, raw_body: str) -> List[ObjectRef]:
  """Extract object references from a POST/PUT/PATCH body."""
  refs: List[ObjectRef] = []
  raw_body = raw_body.strip()
  if not raw_body:
    return refs

  # JSON body
  if raw_body.startswith('{') or raw_body.startswith('['):
    try:
      parsed = json.loads(raw_body)
      for field_name, value in _flatten_json(parsed):
        if _is_id_param(field_name) or _looks_like_id(str(value)):
          refs.append(ObjectRef(
            location=IDORLocation.JSON_BODY,
            param=field_name,
            value=str(value),
            id_type=detect_id_type(str(value)),
            url=url,
            method=method,
            body_context=parsed if isinstance(parsed, dict) else None,
          ))
    except json.JSONDecodeError:
      pass
    return refs

  # form-encoded body
  qs = up.parse_qs(raw_body, keep_blank_values=True)
  for name, values in qs.items():
    value = values[0] if values else ""
    if _is_id_param(name) or _looks_like_id(value):
      refs.append(ObjectRef(
        location=IDORLocation.POST_BODY,
        param=name,
        value=value,
        id_type=detect_id_type(value),
        url=url,
        method=method,
        body_context=raw_body,   # preserve the full raw form string
      ))

  return refs


def extract_from_headers(url: str, method: str,
                         headers: Dict[str, str]) -> List[ObjectRef]:
  """Extract object references from HTTP request headers."""
  refs: List[ObjectRef] = []
  for name, value in headers.items():
    name_lower = name.lower()

    # Known ID-bearing custom headers
    if name_lower in _ID_HEADERS:
      refs.append(ObjectRef(
        location=IDORLocation.HEADER,
        param=name,
        value=value,
        id_type=detect_id_type(value),
        url=url,
        method=method,
        header_name=name,
      ))
      continue

    # Authorization: Bearer <JWT> — extract as JWT_CLAIM ref
    if name_lower == 'authorization':
      stripped = value.strip()
      if stripped.lower().startswith('bearer '):
        token = stripped[7:].strip()
        if token and detect_id_type(token) == IDType.JWT:
          refs.append(ObjectRef(
            location=IDORLocation.JWT_CLAIM,
            param='Authorization',
            value=token,
            id_type=IDType.JWT,
            url=url,
            method=method,
            header_name='Authorization',
          ))
      continue

    # Cookie header — split into individual cookies and extract ID-like ones
    if name_lower == 'cookie':
      for cookie_pair in value.split(';'):
        cookie_pair = cookie_pair.strip()
        if '=' not in cookie_pair:
          continue
        cname, _, cval = cookie_pair.partition('=')
        cname = cname.strip()
        cval  = cval.strip()
        if _is_id_param(cname) or _looks_like_id(cval):
          refs.append(ObjectRef(
            location=IDORLocation.COOKIE,
            param=cname,
            value=cval,
            id_type=detect_id_type(cval),
            url=url,
            method=method,
            header_name='Cookie',
          ))

  return refs


def harvest_ids_from_response(url: str, body: str) -> List[HarvestedID]:
  """
  Parse a JSON response body and extract IDs that may belong to other users.
  These can be fed back into subsequent tamper tests (ID chaining).
  """
  harvested: List[HarvestedID] = []
  body = body.strip()
  if not body.startswith('{') and not body.startswith('['):
    return harvested
  try:
    parsed = json.loads(body)
    for field_name, value in _flatten_json(parsed):
      if field_name.lower() in _OWNERSHIP_KEYS or _is_id_param(field_name):
        if value and str(value) not in ('null', 'None', ''):
          harvested.append(HarvestedID(
            field=field_name,
            value=str(value),
            url=url,
          ))
  except json.JSONDecodeError as exc:
    logger.debug("JSON parse error harvesting IDs from %s: %s", url, exc)
  except Exception as exc:
    logger.debug("Unexpected error harvesting IDs from %s: %s", url, exc)
  return harvested


def extract_all(
  url:     str,
  method:  str,
  body:    str = "",
  headers: Optional[Dict[str, str]] = None,
) -> List[ObjectRef]:
  """Convenience: extract refs from URL + body + headers in one call."""
  refs = extract_from_url(url, method)
  if body:
    refs.extend(extract_from_body(url, method, body))
  if headers:
    refs.extend(extract_from_headers(url, method, headers))
  return refs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_id_param(name: str) -> bool:
  """True if the parameter name is in the known-ID keyword set or matches suffix regex."""
  if name.lower() in {k.lower() for k in _ID_PARAM_KEYWORDS}:
    return True
  return bool(_ID_SUFFIX_RE.search(name))


def _looks_like_id(value: str) -> bool:
  """True if the value itself looks like an ID (integer, UUID, hash, JWT, etc.)"""
  if not value or len(value) > 512:
    return False
  t = detect_id_type(value)
  return t not in (IDType.UNKNOWN, IDType.SLUG)


def _flatten_json(
  obj: Any,
  prefix: str = "",
  depth: int = 0,
) -> Iterator[Tuple[str, Any]]:
  """Recursively yield (dotted_key, scalar_value) pairs from a JSON object."""
  if depth > 5:
    return
  if isinstance(obj, dict):
    for k, v in obj.items():
      full_key = f"{prefix}.{k}" if prefix else k
      if isinstance(v, (dict, list)):
        yield from _flatten_json(v, full_key, depth + 1)
      else:
        yield full_key, v
  elif isinstance(obj, list):
    for i, item in enumerate(obj[:20]):  # limit list depth
      yield from _flatten_json(item, f"{prefix}[{i}]", depth + 1)