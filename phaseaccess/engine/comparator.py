# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/comparator.py
Semantic response diffing for IDOR detection.

Compares a baseline (owner's authenticated response) against a tampered
response and produces a DiffResult with confidence-graded signals.

Signals evaluated:
  1. Status code change                 → LOW
  2. Body hash change (stable)          → MEDIUM (content changed)
  3. Length delta ratio                 → supporting signal
  4. JSON structure change              → MEDIUM
  5. Ownership field present in tampered but not baseline → HIGH
  6. Ownership field VALUE differs      → CONFIRMED (other user's data)
  7. Known-foreign ownership value found → CONFIRMED
  8. Response body unchanged (no IDOR) → NOT_IDOR

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .fingerprint import ResponseFingerprint
from .reporter import Confidence


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

class DiffVerdict(str, Enum):
  CONFIRMED    = "confirmed"     # other user's data in response
  LIKELY       = "likely"        # strong structural signals
  POSSIBLE     = "possible"      # status/length changed
  UNCHANGED    = "unchanged"     # no meaningful diff → probably not IDOR
  ERROR        = "error"         # tampered request failed


@dataclass
class DiffResult:
  verdict:       DiffVerdict
  confidence:    Confidence

  # Human-readable signals
  signals:       List[str] = field(default_factory=list)
  evidence_snippet: str = ""

  # Cross-user ownership leak
  leaked_fields: List[str] = field(default_factory=list)

  # Numeric deltas
  status_delta:  int   = 0
  length_delta:  int   = 0
  length_ratio:  float = 1.0

  def to_dict(self) -> dict:
    return {
      "verdict":          self.verdict,
      "confidence":       self.confidence,
      "signals":          self.signals,
      "evidence_snippet": self.evidence_snippet,
      "leaked_fields":    self.leaked_fields,
      "status_delta":     self.status_delta,
      "length_delta":     self.length_delta,
      "length_ratio":     self.length_ratio,
    }


# ---------------------------------------------------------------------------
# Main comparison function
# ---------------------------------------------------------------------------

def compare(
  baseline:          ResponseFingerprint,
  tampered:          ResponseFingerprint,
  known_foreign_values: Optional[Dict[str, str]] = None,
  is_dual:           bool = False,
) -> DiffResult:
  """
  Compare `baseline` (owner's response) with `tampered` (attacker's response).

  `known_foreign_values` — ownership field values belonging to a *different*
  user (collected in multi-session mode), used to confirm cross-user leakage.

  Returns a DiffResult.
  """
  signals:       List[str] = []
  leaked_fields: List[str] = []
  evidence       = ""

  # 1. Tampered request failed → no verdict
  if tampered.status == 0:
    return DiffResult(
      verdict=DiffVerdict.ERROR,
      confidence=Confidence.LOW,
      signals=["tampered request failed"],
    )

  # 2. Status code delta
  status_delta = tampered.status - baseline.status
  if status_delta != 0:
    signals.append(f"status: {baseline.status} → {tampered.status}")

  # 3. Length delta
  length_delta = tampered.body_length - baseline.body_length
  length_ratio = (
    tampered.body_length / baseline.body_length
    if baseline.body_length > 0
    else float('inf')
  )
  if abs(length_delta) > 50:
    signals.append(
      f"body length: {baseline.body_length} → {tampered.body_length} "
      f"(delta {length_delta:+d})"
    )

  # 4. Stable hash change (content changed meaningfully)
  hash_changed = baseline.stable_hash != tampered.stable_hash

  # 5. JSON structure change
  struct_changed = (
    baseline.structure_sig != tampered.structure_sig
    and bool(baseline.structure_sig)
    and bool(tampered.structure_sig)
  )
  if struct_changed:
    signals.append(
      f"JSON structure changed: {baseline.structure_sig!r} → "
      f"{tampered.structure_sig!r}"
    )

  # 6. Ownership field analysis
  base_ownership    = baseline.ownership_values
  tampered_ownership = tampered.ownership_values

  # "Ambient session" keys (profile_username, greeting_name, heading_username)
  # are extracted from nav-bar and greeting elements that naturally show the
  # currently logged-in user's identity.  In dual-session testing they ALWAYS
  # differ between sessions because each user's nav shows their own name —
  # this is not evidence of IDOR.
  _AMBIENT_KEYS = frozenset({'profile_username', 'greeting_name', 'heading_username'})

  for field_name, tampered_val in tampered_ownership.items():
    base_val = base_ownership.get(field_name)

    if field_name in _AMBIENT_KEYS:
      # Only flag if the *baseline* identity value appears in the tampered body.
      if (
        base_val
        and len(base_val) >= 6
        and base_val != tampered_val
        and base_val in tampered.body
      ):
        signals.append(
          f"owner identity {field_name!r} present in tampered: {base_val!r}"
        )
        leaked_fields.append(field_name)
        evidence = f"{field_name}: {base_val!r} found in tampered response"
      continue

    if base_val is None:
      # Ownership field appeared that wasn't in baseline
      signals.append(f"ownership field appeared: {field_name}={tampered_val!r}")
      leaked_fields.append(field_name)

    elif base_val != tampered_val:
      # Ownership field value changed — most likely cross-user
      signals.append(
        f"ownership field {field_name!r} changed: "
        f"{base_val!r} → {tampered_val!r}"
      )
      leaked_fields.append(field_name)
      evidence = (
        f"{field_name}: baseline={base_val!r}, tampered={tampered_val!r}"
      )

  # 7. Known-foreign value present in tampered body
  if known_foreign_values:
    for field_name, foreign_val in known_foreign_values.items():
      if field_name in _AMBIENT_KEYS:
        # Ambient session keys (nav bar identity) naturally appear in every
        # response for the session they belong to — don't use them as
        # cross-user leakage evidence.
        continue
      if (
        foreign_val
        and len(foreign_val) >= 8
        and foreign_val in tampered.body
        and foreign_val not in baseline.body
      ):
        signals.append(
          f"CONFIRMED: foreign value {field_name}={foreign_val!r} "
          f"present in tampered response"
        )
        leaked_fields.append(field_name)
        evidence = (
          f"Foreign {field_name}={foreign_val!r} appeared in response "
          f"(not in baseline)"
        )
        snippet = _extract_snippet(tampered.body, foreign_val)
        if snippet:
          evidence += f" | snippet: {snippet}"

  # 8. Timing oracle — significant latency difference may indicate backend
  #    actually fetched a resource (e.g. a slow DB hit vs fast 403/404 path).
  #    Only fire when status codes are both 2xx (i.e. not a 404 fast-path).
  timing_signal = False
  if (
    baseline.elapsed_ms >= 50
    and tampered.elapsed_ms > 0
    and baseline.status in range(200, 300)
    and tampered.status in range(200, 300)
  ):
    ratio = tampered.elapsed_ms / baseline.elapsed_ms
    if ratio > 5.0 or ratio < 0.2:
      signals.append(
        f"timing delta: baseline {baseline.elapsed_ms:.0f}ms "
        f"→ tampered {tampered.elapsed_ms:.0f}ms (ratio {ratio:.1f}x)"
      )
      timing_signal = True

  # --- Derive verdict ---
  _is_json = bool(baseline.structure_sig or tampered.structure_sig)
  verdict, confidence = _verdict(
    status_delta=status_delta,
    hash_changed=hash_changed,
    struct_changed=struct_changed,
    leaked_fields=leaked_fields,
    signals=signals,
    length_delta=length_delta,
    length_ratio=length_ratio,
    baseline_status=baseline.status,
    tampered_status=tampered.status,
    timing_signal=timing_signal,
    is_json=_is_json,
    is_dual=is_dual,
  )

  # Extract diff snippet if no evidence yet
  if not evidence and hash_changed and verdict not in (
    DiffVerdict.UNCHANGED, DiffVerdict.ERROR
  ):
    evidence = _body_diff_snippet(baseline.body, tampered.body)

  return DiffResult(
    verdict=verdict,
    confidence=confidence,
    signals=signals,
    evidence_snippet=evidence[:500],
    leaked_fields=leaked_fields,
    status_delta=status_delta,
    length_delta=length_delta,
    length_ratio=round(length_ratio, 3),
  )


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def _verdict(
  status_delta:     int,
  hash_changed:     bool,
  struct_changed:   bool,
  leaked_fields:    List[str],
  signals:          List[str],
  length_delta:     int,
  length_ratio:     float,
  baseline_status:  int,
  tampered_status:  int,
  timing_signal:    bool = False,
  is_json:          bool = False,
  is_dual:          bool = False,
) -> Tuple[DiffVerdict, Confidence]:

  # If tampered request was rejected (4xx/5xx) when baseline succeeded,
  # the server correctly enforced access control — not an IDOR signal.
  if baseline_status in range(200, 300) and tampered_status >= 400:
    return DiffVerdict.UNCHANGED, Confidence.LOW

  # Both baseline and tampered are error responses — different error codes
  # between them (e.g. 405 vs 404) carry no IDOR meaning.
  if baseline_status >= 400 and tampered_status >= 400:
    return DiffVerdict.UNCHANGED, Confidence.LOW

  # CONFIRMED: ownership field with foreign value proven
  if any('CONFIRMED' in s for s in signals):
    return DiffVerdict.CONFIRMED, Confidence.CONFIRMED

  # CONFIRMED: ownership field value changed (cross-user data)
  if leaked_fields and any('changed' in s for s in signals):
    return DiffVerdict.CONFIRMED, Confidence.HIGH

  # LIKELY: ownership field appeared + content changed
  if leaked_fields and hash_changed:
    return DiffVerdict.LIKELY, Confidence.HIGH

  # LIKELY: 200 response when baseline was 403/404 + content looks like data
  if (
    baseline_status in (401, 403, 404)
    and tampered_status == 200
    and hash_changed
  ):
    return DiffVerdict.LIKELY, Confidence.HIGH

  # POSSIBLE: JSON structure change is always a strong signal
  if struct_changed:
    return DiffVerdict.POSSIBLE, Confidence.MEDIUM

  # POSSIBLE: substantial content change, but only for JSON responses.
  # HTML body changes alone are too noisy — public pages, different content
  # items at different IDs, and auth-state nav differences all produce false
  # positives without a JSON ownership-field or structural signal.
  if is_json and hash_changed and abs(length_delta) > 100:
    return DiffVerdict.POSSIBLE, Confidence.MEDIUM

  # POSSIBLE: write IDOR — both sessions redirected (3xx) but to different
  # locations. A POST/PUT/PATCH that returns 302 to /resource/<id> and the
  # redirect target changes when the path ID is tampered means the write
  # affected a different user's resource, even though no data is returned.
  if (
    baseline_status in range(300, 400)
    and tampered_status in range(300, 400)
    and hash_changed
  ):
    return DiffVerdict.POSSIBLE, Confidence.MEDIUM

  # POSSIBLE: timing oracle fired (significant latency difference with 2xx/2xx)
  if timing_signal:
    return DiffVerdict.POSSIBLE, Confidence.LOW

  # LOW: only status code changed (could be rate limit, CSRF, etc.)
  if status_delta != 0:
    return DiffVerdict.POSSIBLE, Confidence.LOW

  # No meaningful change → not IDOR
  return DiffVerdict.UNCHANGED, Confidence.LOW


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_snippet(body: str, needle: str, context: int = 80) -> str:
  """Return `context` chars around the first occurrence of `needle` in body."""
  idx = body.find(needle)
  if idx < 0:
    return ""
  start = max(0, idx - context)
  end   = min(len(body), idx + len(needle) + context)
  snippet = body[start:end].replace('\n', ' ')
  return f"...{snippet}..." if start > 0 else f"{snippet}..."


def _body_diff_snippet(baseline: str, tampered: str, max_lines: int = 5) -> str:
  """
  Generate a compact unified-diff snippet highlighting the first
  meaningful difference between baseline and tampered bodies.
  """
  a_lines = baseline.splitlines(keepends=True)[:200]
  b_lines = tampered.splitlines(keepends=True)[:200]

  diff = list(difflib.unified_diff(
    a_lines, b_lines,
    fromfile='baseline', tofile='tampered',
    n=1,
  ))

  # Return first `max_lines` changed lines (+ and -)
  changes = [l.rstrip() for l in diff if l.startswith(('+', '-')) and not l.startswith(('+++', '---'))]
  return ' | '.join(changes[:max_lines])