"""
PhaseAccess — engine/har_import.py
Import HTTP traffic from HAR (HTTP Archive) and Burp Suite XML files.

Produces a list of ScanTarget dicts that can be fed directly into the scanner:
  [{"url": ..., "method": ..., "body": ..., "headers": {...}}, ...]

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import base64
import json
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

# A minimal description of one HTTP request to test
ScanTarget = Dict[str, Any]   # keys: url, method, body, headers


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def load_har(path: str) -> List[ScanTarget]:
  """
  Parse a HAR file (JSON) and return a list of ScanTargets.

  Only HTTP/HTTPS requests are included.  Requests with no URL or with
  non-http(s) schemes are silently skipped.
  """
  try:
    with open(path, encoding='utf-8') as fh:
      har = json.load(fh)
  except (OSError, json.JSONDecodeError) as exc:
    logger.error("Failed to load HAR file %r: %s", path, exc)
    return []

  entries = (
    har.get('log', {}).get('entries', [])
    or har.get('entries', [])
  )

  targets: List[ScanTarget] = []
  for entry in entries:
    req = entry.get('request', {})
    target = _parse_har_request(req)
    if target:
      targets.append(target)

  logger.info("Loaded %d request(s) from HAR file %r", len(targets), path)
  return targets


def load_burp_xml(path: str) -> List[ScanTarget]:
  """
  Parse a Burp Suite XML export and return a list of ScanTargets.

  Burp XML structure:
    <items burpVersion="...">
      <item>
        <url>...</url>
        <method>...</method>
        <request base64="true">...</request>
        ...
      </item>
    </items>
  """
  try:
    tree = ET.parse(path)
  except (OSError, ET.ParseError) as exc:
    logger.error("Failed to parse Burp XML file %r: %s", path, exc)
    return []

  root = tree.getroot()
  # Root may be <items> or a wrapper
  items = root.findall('item') or root.findall('.//item')

  targets: List[ScanTarget] = []
  for item in items:
    target = _parse_burp_item(item)
    if target:
      targets.append(target)

  logger.info("Loaded %d request(s) from Burp XML file %r", len(targets), path)
  return targets


def load_file(path: str) -> List[ScanTarget]:
  """
  Auto-detect format (HAR JSON or Burp XML) and load targets.
  Falls back gracefully on parse errors.
  """
  path_lower = path.lower()
  if path_lower.endswith('.xml'):
    return load_burp_xml(path)
  # Default: try HAR (JSON), fall back to Burp XML
  try:
    with open(path, encoding='utf-8') as fh:
      first_char = fh.read(1)
    if first_char == '<':
      return load_burp_xml(path)
    return load_har(path)
  except OSError as exc:
    logger.error("Cannot open import file %r: %s", path, exc)
    return []


# ---------------------------------------------------------------------------
# HAR parser helpers
# ---------------------------------------------------------------------------

def _parse_har_request(req: Dict[str, Any]) -> Optional[ScanTarget]:
  url = req.get('url', '')
  if not url or not url.startswith(('http://', 'https://')):
    return None

  method = req.get('method', 'GET').upper()

  # Headers
  headers: Dict[str, str] = {}
  for h in req.get('headers', []):
    name  = h.get('name', '')
    value = h.get('value', '')
    if name and not name.startswith(':'):   # skip HTTP/2 pseudo-headers
      headers[name] = value

  # Request body
  body = ''
  post_data = req.get('postData', {}) or {}
  if post_data:
    body = post_data.get('text', '') or ''
    # Some HAR exporters encode the body in params list
    if not body and post_data.get('params'):
      import urllib.parse as up
      body = up.urlencode({
        p['name']: p.get('value', '')
        for p in post_data['params']
      })

  return {
    'url':     url,
    'method':  method,
    'body':    body,
    'headers': headers,
  }


# ---------------------------------------------------------------------------
# Burp XML parser helpers
# ---------------------------------------------------------------------------

def _parse_burp_item(item: ET.Element) -> Optional[ScanTarget]:
  url_el    = item.find('url')
  method_el = item.find('method')
  req_el    = item.find('request')

  url = (url_el.text or '').strip() if url_el is not None else ''
  if not url or not url.startswith(('http://', 'https://')):
    return None

  method = (method_el.text or 'GET').strip().upper() if method_el is not None else 'GET'

  headers: Dict[str, str] = {}
  body = ''

  if req_el is not None:
    raw_req = req_el.text or ''
    is_b64  = req_el.get('base64', 'false').lower() == 'true'
    if is_b64:
      try:
        raw_req = base64.b64decode(raw_req).decode('utf-8', errors='replace')
      except Exception as exc:
        logger.debug("Burp XML base64 decode failed: %s", exc)
        raw_req = ''

    headers, body = _parse_raw_http_request(raw_req)

  return {
    'url':     url,
    'method':  method,
    'body':    body,
    'headers': headers,
  }


def _parse_raw_http_request(raw: str) -> tuple[Dict[str, str], str]:
  """
  Parse a raw HTTP/1.1 request string into (headers_dict, body_str).
  The first line (request-line) is discarded; we already have URL + method.
  """
  headers: Dict[str, str] = {}
  body = ''

  # Split on the blank line separating headers from body
  if '\r\n\r\n' in raw:
    header_part, _, body = raw.partition('\r\n\r\n')
  elif '\n\n' in raw:
    header_part, _, body = raw.partition('\n\n')
  else:
    header_part = raw

  lines = header_part.replace('\r\n', '\n').split('\n')
  # Skip request line (first non-empty line starting with a method)
  start = 1 if lines and lines[0].startswith(('GET ', 'POST ', 'PUT ', 'PATCH ', 'DELETE ')) else 0
  for line in lines[start:]:
    if ':' in line:
      name, _, value = line.partition(':')
      name  = name.strip()
      value = value.strip()
      if name:
        headers[name] = value

  return headers, body.strip()
