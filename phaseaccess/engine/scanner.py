# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/scanner.py
Main IDOR scan orchestrator.

Flow:
  1. Parse ScanOptions into a SessionPair + target list.
  2. For each endpoint:
     a. Fetch baseline (session_a).
     b. Extract all ObjectRefs from URL + body + headers.
     c. For each ref, generate tamper candidates.
     d. Fire tampered requests (session_b if dual, else session_a).
     e. Compare fingerprints with comparator.
     f. If verdict is POSSIBLE or better → create IDORFinding.
  3. Additional checks: method bypass, param pollution.
  4. Harvest IDs from responses for cross-endpoint chaining.
  5. Return ScanResult.

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import concurrent.futures
import json as _json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

from .reporter import (
  IDORFinding, IDORType, IDORLocation, Confidence, IDType, ScanResult,
)
from .extractor import (
  ObjectRef, extract_all, harvest_ids_from_response,
)
from .id_engine import generate_candidates, detect_id_type
from .fingerprint import build_baseline, ResponseFingerprint
from .tamper import send_tampered, send_method_variants, send_param_pollution
from .comparator import compare, DiffVerdict
from .session import SessionPair, pair_from_config


# ---------------------------------------------------------------------------
# ScanOptions
# ---------------------------------------------------------------------------

@dataclass
class ScanOptions:
  # Session credentials
  session_a_headers: Dict[str, str] = field(default_factory=dict)
  session_a_cookies: str = ""
  session_a_label:   str = "session_a"

  session_b_headers: Dict[str, str] = field(default_factory=dict)
  session_b_cookies: str = ""
  session_b_label:   str = ""          # empty = single-session mode

  # Request
  method:  str = "GET"
  body:    str = ""
  proxy:   str = ""
  timeout: int = 15

  # TLS / network
  verify_ssl: bool  = True    # set False to skip certificate verification
  delay:      float = 0.0     # seconds between requests (rate limiting)
  user_agent: str   = "PhaseAccess/1.0"

  # Scan breadth
  threads:          int = 5
  max_candidates:   int = 10           # tamper candidates per parameter
  method_bypass:    bool = True        # test HTTP method bypass
  param_pollution:  bool = True        # test HPP
  mass_assignment:  bool = True        # test mass assignment on JSON body endpoints
  soft_delete:      bool = True        # test soft-delete bypass via hint params
  blind_idor:       bool = True        # detect blind IDOR via status-only signals

  # Extra endpoints to test (in addition to the primary target)
  extra_urls: List[str] = field(default_factory=list)

  # Callback for live progress
  on_log: Optional[Callable[[str], None]] = None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan(target: str, opts: ScanOptions) -> ScanResult:
  """Run a full PhaseAccess IDOR scan and return ScanResult."""
  result = ScanResult(
    target=target,
    session_a_label=opts.session_a_label,
    session_b_label=opts.session_b_label,
  )

  def log(msg: str) -> None:
    result.log.append(msg)
    if opts.on_log:
      opts.on_log(msg)

  # Build session pair
  session_pair = _build_session_pair(opts)

  all_urls = [target] + (opts.extra_urls or [])
  log(f"[*] PhaseAccess starting — {len(all_urls)} endpoint(s)")
  log(f"[*] Mode: {'dual-session' if session_pair.is_dual else 'single-session'}")
  if not opts.verify_ssl:
    log("[!] SSL certificate verification disabled (--insecure)")

  # Harvested IDs from session_a responses (for ID chaining)
  harvested_pool: Dict[str, List[str]] = {}
  harvested_lock = threading.Lock()

  with concurrent.futures.ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futures = {
      pool.submit(
        _scan_endpoint,
        url, opts, session_pair, harvested_pool, harvested_lock, log,
      ): url
      for url in all_urls
    }
    for future in concurrent.futures.as_completed(futures):
      url = futures[future]
      try:
        ep_result = future.result()
        result.findings.extend(ep_result.findings)
        result.endpoints_tested += ep_result.endpoints_tested
        result.parameters_tested += ep_result.parameters_tested
        result.requests_sent += ep_result.requests_sent
        result.errors.extend(ep_result.errors)
        # Merge harvested IDs (lock not needed here; futures are already done)
        for k, vals in ep_result.harvested_ids.items():
          harvested_pool.setdefault(k, []).extend(vals)
      except Exception as e:
        result.errors.append(f"Endpoint {url} failed: {e}")

  result.harvested_ids = harvested_pool
  result.id_types_found = list({
    f.id_type for f in result.findings
  })

  # Deduplicate: keep highest-confidence finding per (url, parameter) pair
  result.findings = _deduplicate_findings(result.findings)

  result.finish()
  log(f"[*] Scan complete — {result.total_findings} finding(s) in {result.duration_s}s")
  return result


# ---------------------------------------------------------------------------
# Per-endpoint scan
# ---------------------------------------------------------------------------

def _scan_endpoint(
  url:           str,
  opts:          ScanOptions,
  pair:          SessionPair,
  harvested_pool: Dict[str, List[str]],
  harvested_lock: threading.Lock,
  log:           Callable[[str], None],
) -> ScanResult:
  """Scan a single endpoint and return a partial ScanResult."""
  partial = ScanResult(target=url)

  # 1. Baseline (session_a)
  log(f"[~] Fetching baseline: {url}")
  baseline = build_baseline(
    url=url,
    method=opts.method,
    headers=pair.headers_for('a'),
    body=opts.body,
    cookies=pair.cookies_for('a'),
    proxy=opts.proxy,
    timeout=opts.timeout,
    verify_ssl=opts.verify_ssl,
    delay=opts.delay,
  )
  if baseline is None:
    partial.errors.append(f"Baseline fetch failed: {url}")
    return partial

  partial.requests_sent += 1

  # Harvest IDs from baseline response (for chaining)
  harvested = harvest_ids_from_response(url, baseline.body)
  for h in harvested:
    partial.harvested_ids.setdefault(h.field, []).append(h.value)

  # 2. Extract object refs
  refs = extract_all(url, opts.method, opts.body, pair.headers_for('a'))
  if not refs:
    log(f"[~] No object references found in {url}")
    return partial

  partial.endpoints_tested = 1
  log(f"[~] Found {len(refs)} object ref(s) in {url}")

  # Known foreign values from session_b's harvest (for cross-session confirmation)
  known_foreign: Dict[str, str] = {}
  if pair.is_dual and pair.session_b:
    b_baseline = build_baseline(
      url=url,
      method=opts.method,
      headers=pair.headers_for('b'),
      body=opts.body,
      cookies=pair.cookies_for('b'),
      proxy=opts.proxy,
      timeout=opts.timeout,
      verify_ssl=opts.verify_ssl,
      delay=opts.delay,
    )
    partial.requests_sent += 1
    if b_baseline:
      known_foreign = b_baseline.ownership_values
      # Also add from pool
      for field_name, vals in harvested_pool.items():
        if vals:
          known_foreign.setdefault(field_name, vals[0])

  # 3. Test each ref
  for ref in refs:
    partial.parameters_tested += 1
    log(f"[~] Testing {ref.location} {ref.param}={ref.value!r} ({ref.id_type})")

    # Foreign IDs from session_b's harvest
    foreign_ids: List[str] = []
    if pair.is_dual:
      for vals in harvested_pool.values():
        foreign_ids.extend(vals[:2])

    candidates = generate_candidates(
      ref.value,
      ref.id_type,
      foreign_ids=foreign_ids or None,
      count=opts.max_candidates,
    )

    for cand in candidates:
      # Use session_b headers if dual, else session_a
      req_headers = pair.headers_for('b') if pair.is_dual else pair.headers_for('a')
      req_cookies = pair.cookies_for('b') if pair.is_dual else pair.cookies_for('a')

      tamper_result = send_tampered(
        ref=ref,
        tampered_value=cand.value,
        description=cand.description,
        extra_headers=req_headers,
        cookies=req_cookies,
        proxy=opts.proxy,
        timeout=opts.timeout,
        verify_ssl=opts.verify_ssl,
        delay=opts.delay,
        baseline_body=baseline.body,
      )
      partial.requests_sent += 1

      if tamper_result is None:
        continue

      diff = compare(
        baseline=baseline,
        tampered=tamper_result.fingerprint,
        known_foreign_values=known_foreign or None,
      )

      if diff.verdict in (DiffVerdict.CONFIRMED, DiffVerdict.LIKELY, DiffVerdict.POSSIBLE):
        idor_type = _classify_idor_type(
          ref, cand.is_foreign, pair.is_dual, diff.verdict
        )
        finding = IDORFinding(
          idor_type=idor_type,
          confidence=diff.confidence,
          location=ref.location,
          url=url,
          method=opts.method,
          parameter=ref.param,
          id_type=ref.id_type,
          original_value=ref.value,
          tampered_value=cand.value,
          baseline_status=baseline.status,
          tampered_status=tamper_result.fingerprint.status,
          baseline_length=baseline.body_length,
          tampered_length=tamper_result.fingerprint.body_length,
          owner_fields_leaked=diff.leaked_fields,
          evidence_snippet=diff.evidence_snippet,
          session_a_label=opts.session_a_label,
          session_b_label=opts.session_b_label,
          notes="; ".join(diff.signals[:5]),
          curl_command=_build_curl_command(
            tamper_result.effective_url,
            opts.method,
            tamper_result.effective_headers,
            tamper_result.effective_body,
          ),
        )
        partial.findings.append(finding)
        log(
          f"[+] {diff.confidence.upper()} {idor_type} — "
          f"{ref.param}={cand.value!r} @ {url}"
        )
        # Stop on first confirmed finding for this ref to avoid noise
        if diff.verdict == DiffVerdict.CONFIRMED:
          break

        # Skip blind IDOR — we already have a regular finding for this candidate
        continue

      # 4b. Blind IDOR check — only when normal comparator produced no finding
      if opts.blind_idor:
        blind = _check_blind_idor(
          ref, baseline, tamper_result.fingerprint,
          cand.value, cand.description,
        )
        if blind:
          partial.findings.append(blind)
          log(f"[+] BLIND IDOR — {ref.param}={cand.value!r} @ {url}")
          break  # one blind finding per ref is enough

    # 4. Method bypass check
    if opts.method_bypass:
      method_results = send_method_variants(
        ref=ref,
        extra_headers=pair.headers_for('b') if pair.is_dual else pair.headers_for('a'),
        cookies=pair.cookies_for('b') if pair.is_dual else pair.cookies_for('a'),
        proxy=opts.proxy,
        timeout=opts.timeout,
        verify_ssl=opts.verify_ssl,
        delay=opts.delay,
      )
      partial.requests_sent += len(method_results)
      for mr in method_results:
        diff = compare(baseline, mr.fingerprint, known_foreign or None)
        if diff.verdict in (DiffVerdict.CONFIRMED, DiffVerdict.LIKELY):
          partial.findings.append(IDORFinding(
            idor_type=IDORType.METHOD_BYPASS,
            confidence=diff.confidence,
            location=ref.location,
            url=url,
            method=mr.ref.method,
            parameter=ref.param,
            id_type=ref.id_type,
            original_value=ref.value,
            tampered_value=ref.value,
            baseline_status=baseline.status,
            tampered_status=mr.fingerprint.status,
            baseline_length=baseline.body_length,
            tampered_length=mr.fingerprint.body_length,
            owner_fields_leaked=diff.leaked_fields,
            evidence_snippet=diff.evidence_snippet,
            session_a_label=opts.session_a_label,
            session_b_label=opts.session_b_label,
            notes=f"method bypass via {mr.ref.method}",
          ))
          log(f"[+] METHOD BYPASS {mr.ref.method} {ref.param} @ {url}")

    # 5. Param pollution
    if opts.param_pollution and ref.location == IDORLocation.QUERY_PARAM and candidates:
      pp_result = send_param_pollution(
        ref=ref,
        tampered_value=candidates[0].value,
        extra_headers=pair.headers_for('b') if pair.is_dual else pair.headers_for('a'),
        cookies=pair.cookies_for('b') if pair.is_dual else pair.cookies_for('a'),
        proxy=opts.proxy,
        timeout=opts.timeout,
        verify_ssl=opts.verify_ssl,
        delay=opts.delay,
      )
      partial.requests_sent += 1
      if pp_result:
        diff = compare(baseline, pp_result.fingerprint, known_foreign or None)
        if diff.verdict in (DiffVerdict.CONFIRMED, DiffVerdict.LIKELY):
          partial.findings.append(IDORFinding(
            idor_type=IDORType.PARAM_POLLUTION,
            confidence=diff.confidence,
            location=ref.location,
            url=url,
            method=opts.method,
            parameter=ref.param,
            id_type=ref.id_type,
            original_value=ref.value,
            tampered_value=candidates[0].value,
            baseline_status=baseline.status,
            tampered_status=pp_result.fingerprint.status,
            baseline_length=baseline.body_length,
            tampered_length=pp_result.fingerprint.body_length,
            owner_fields_leaked=diff.leaked_fields,
            evidence_snippet=diff.evidence_snippet,
            session_a_label=opts.session_a_label,
            session_b_label=opts.session_b_label,
            notes="HTTP parameter pollution",
          ))

    # 6. Mass assignment check
    if opts.mass_assignment:
      # Use first foreign ID if available, otherwise first candidate value
      foreign_id = (
        list(known_foreign.values())[0] if known_foreign
        else (candidates[0].value if candidates else "")
      )
      ma_finding = _check_mass_assignment(
        ref, baseline, foreign_id, opts, pair,
      )
      if ma_finding:
        partial.requests_sent += 1
        partial.findings.append(ma_finding)
        log(f"[+] MASS ASSIGNMENT — {ref.param} @ {url}")

    # 7. Soft-delete check
    if opts.soft_delete:
      sd_finding = _check_soft_delete(ref, baseline, opts, pair)
      if sd_finding:
        partial.requests_sent += len(_SOFT_DELETE_HINTS)
        partial.findings.append(sd_finding)
        log(f"[+] SOFT-DELETE BYPASS — {ref.param} @ {url}")

  return partial


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_session_pair(opts: ScanOptions) -> SessionPair:
  from .session import Session
  ua = opts.user_agent or "PhaseAccess/1.0"
  a_headers = dict(opts.session_a_headers)
  a_headers.setdefault('User-Agent', ua)
  session_a = Session(
    label=opts.session_a_label,
    headers=a_headers,
    cookies=opts.session_a_cookies,
  )
  session_b: Optional[Session] = None
  if opts.session_b_label:
    b_headers = dict(opts.session_b_headers)
    b_headers.setdefault('User-Agent', ua)
    session_b = Session(
      label=opts.session_b_label,
      headers=b_headers,
      cookies=opts.session_b_cookies,
    )
  return SessionPair(session_a=session_a, session_b=session_b)


def _deduplicate_findings(findings: List[IDORFinding]) -> List[IDORFinding]:
  """
  For each (url, parameter, idor_type) tuple keep only the finding with the
  highest confidence.  Preserves original order (first occurrence wins on tie).
  """
  _CONF_ORDER = [
    Confidence.CONFIRMED,
    Confidence.HIGH,
    Confidence.MEDIUM,
    Confidence.LOW,
    Confidence.INFO,
  ]

  def _rank(c: str) -> int:
    try:
      return _CONF_ORDER.index(c)
    except ValueError:
      return len(_CONF_ORDER)

  best: Dict[tuple, IDORFinding] = {}
  for f in findings:
    key = (f.url, f.parameter, f.idor_type)
    existing = best.get(key)
    if existing is None or _rank(f.confidence) < _rank(existing.confidence):
      best[key] = f

  # Restore original ordering
  seen: set = set()
  result: List[IDORFinding] = []
  for f in findings:
    key = (f.url, f.parameter, f.idor_type)
    if key not in seen and best.get(key) is f:
      seen.add(key)
      result.append(f)
  return result


def _classify_idor_type(
  ref:        ObjectRef,
  is_foreign: bool,
  is_dual:    bool,
  verdict:    DiffVerdict,
) -> IDORType:
  if is_dual and is_foreign:
    return IDORType.HORIZONTAL
  if is_dual:
    return IDORType.VERTICAL
  return IDORType.HORIZONTAL


# ---------------------------------------------------------------------------
# Mass-assignment check
# ---------------------------------------------------------------------------

# Ownership field names we try to inject
_MA_FIELDS = [
  "user_id", "owner_id", "account_id", "userId", "ownerId", "accountId",
  "created_by", "createdBy", "author_id", "authorId",
]

def _check_mass_assignment(
  ref:        ObjectRef,
  baseline:   ResponseFingerprint,
  foreign_id: str,
  opts:       "ScanOptions",
  pair:       "SessionPair",
) -> Optional[IDORFinding]:
  """
  Inject ownership fields into a JSON body and check whether the server
  accepts/reflects them back.  Only meaningful for JSON body requests.
  """
  if ref.location not in (IDORLocation.JSON_BODY, IDORLocation.POST_BODY):
    return None
  if not foreign_id:
    return None

  # Build an injected body
  if ref.location == IDORLocation.JSON_BODY and isinstance(ref.body_context, dict):
    injected = dict(ref.body_context)
  elif ref.location == IDORLocation.POST_BODY and isinstance(ref.body_context, str):
    import urllib.parse as _up2
    injected = {k: v[0] for k, v in _up2.parse_qs(
        ref.body_context, keep_blank_values=True).items()}
  else:
    injected = {}

  # Add all ownership field candidates with the foreign ID
  for f in _MA_FIELDS:
    injected[f] = foreign_id

  body_str = _json.dumps(injected)

  req_headers = dict(pair.headers_for('a'))
  req_headers.setdefault('Content-Type', 'application/json')
  req_headers.setdefault('User-Agent', 'PhaseAccess/1.0')
  if pair.cookies_for('a'):
    req_headers.setdefault('Cookie', pair.cookies_for('a'))

  fp = _do_single_request(
    ref.url, ref.method, req_headers, body_str,
    opts.proxy, opts.timeout, opts.verify_ssl, opts.delay,
  )
  if fp is None:
    return None

  diff = compare(baseline, fp, None)

  # Signal: server reflected one of the injected ownership fields in its response
  if diff.verdict not in (DiffVerdict.CONFIRMED, DiffVerdict.LIKELY, DiffVerdict.POSSIBLE):
    return None

  # Stronger signal: the injected foreign_id actually shows up in the response
  injected_reflected = foreign_id in fp.body

  confidence = diff.confidence
  if injected_reflected and confidence not in (Confidence.CONFIRMED, Confidence.HIGH):
    confidence = Confidence.HIGH

  return IDORFinding(
    idor_type=IDORType.MASS_ASSIGNMENT,
    confidence=confidence,
    location=ref.location,
    url=ref.url,
    method=ref.method,
    parameter=", ".join(_MA_FIELDS[:4]) + " ...",
    id_type=ref.id_type,
    original_value=ref.value,
    tampered_value=foreign_id,
    baseline_status=baseline.status,
    tampered_status=fp.status,
    baseline_length=baseline.body_length,
    tampered_length=fp.body_length,
    owner_fields_leaked=diff.leaked_fields,
    evidence_snippet=diff.evidence_snippet,
    session_a_label=opts.session_a_label,
    session_b_label=opts.session_b_label,
    notes="mass assignment: injected ownership field accepted" + (
      "; injected value reflected in response" if injected_reflected else ""
    ),
  )


# ---------------------------------------------------------------------------
# Soft-delete check
# ---------------------------------------------------------------------------

# Query params that may reveal soft-deleted resources
_SOFT_DELETE_HINTS: List[tuple[str, str]] = [
  ("include_deleted", "true"),
  ("show_deleted",    "1"),
  ("deleted",         "true"),
  ("status",          "deleted"),
  ("archived",        "true"),
  ("include_archived","true"),
  ("with_trashed",    "1"),
]

def _check_soft_delete(
  ref:      ObjectRef,
  baseline: ResponseFingerprint,
  opts:     "ScanOptions",
  pair:     "SessionPair",
) -> Optional[IDORFinding]:
  """
  When a tampered request returns 404 (resource not found / deleted), retry
  with soft-delete hint parameters to see if the resource is still accessible.
  """
  import urllib.parse as _up

  req_headers = dict(pair.headers_for('a'))
  req_headers.setdefault('User-Agent', 'PhaseAccess/1.0')
  if pair.cookies_for('a'):
    req_headers.setdefault('Cookie', pair.cookies_for('a'))

  for param, value in _SOFT_DELETE_HINTS:
    parsed  = _up.urlparse(ref.url)
    qs      = _up.parse_qsl(parsed.query, keep_blank_values=True)
    qs.append((param, value))
    hinted_url = _up.urlunparse(parsed._replace(query=_up.urlencode(qs)))

    fp = _do_single_request(
      hinted_url, ref.method, req_headers, "",
      opts.proxy, opts.timeout, opts.verify_ssl, opts.delay,
    )
    if fp is None:
      continue

    # Positive signal: 404 baseline but 200 with the hint param
    if baseline.status == 404 and fp.status == 200 and fp.body_length > 50:
      return IDORFinding(
        idor_type=IDORType.SOFT_DELETE,
        confidence=Confidence.HIGH,
        location=IDORLocation.QUERY_PARAM,
        url=ref.url,
        method=ref.method,
        parameter=param,
        id_type=ref.id_type,
        original_value=ref.value,
        tampered_value=value,
        baseline_status=baseline.status,
        tampered_status=fp.status,
        baseline_length=baseline.body_length,
        tampered_length=fp.body_length,
        owner_fields_leaked=[],
        evidence_snippet=fp.body[:500],
        session_a_label=opts.session_a_label,
        session_b_label=opts.session_b_label,
        notes=f"soft-delete bypass: {param}={value} reveals deleted resource",
      )

    # Weaker signal: same-family success, body grew significantly
    if fp.status == 200 and baseline.status == 200:
      growth = (fp.body_length - baseline.body_length) / max(baseline.body_length, 1)
      if growth > 0.3 and fp.stable_hash != baseline.stable_hash:
        return IDORFinding(
          idor_type=IDORType.SOFT_DELETE,
          confidence=Confidence.MEDIUM,
          location=IDORLocation.QUERY_PARAM,
          url=ref.url,
          method=ref.method,
          parameter=param,
          id_type=ref.id_type,
          original_value=ref.value,
          tampered_value=value,
          baseline_status=baseline.status,
          tampered_status=fp.status,
          baseline_length=baseline.body_length,
          tampered_length=fp.body_length,
          owner_fields_leaked=[],
          evidence_snippet=fp.body[:500],
          session_a_label=opts.session_a_label,
          session_b_label=opts.session_b_label,
          notes=f"soft-delete bypass: {param}={value} returns extra content",
        )

  return None


# ---------------------------------------------------------------------------
# Blind IDOR check
# ---------------------------------------------------------------------------

def _check_blind_idor(
  ref:            ObjectRef,
  baseline:       ResponseFingerprint,
  tamper_fp:      ResponseFingerprint,
  tampered_value: str,
  description:    str,
) -> Optional[IDORFinding]:
  """
  Detect blind IDOR: the tampered request produced a meaningful status-code
  change (suggesting access to a resource) but returned no body content,
  so a normal comparator diff would score low.

  Signals:
    - Baseline returned 403/404/405; tampered returned 200/201/202/204
    - Tampered body is empty or very short (< 100 bytes) — no data leaked
  """
  _DENY_CODES  = {403, 404, 405, 401}
  _ACCESS_CODES = {200, 201, 202, 204}

  if baseline.status not in _DENY_CODES:
    return None
  if tamper_fp.status not in _ACCESS_CODES:
    return None
  # If there IS substantial body content, the normal comparator handles it
  if tamper_fp.body_length > 100:
    return None

  return IDORFinding(
    idor_type=IDORType.BLIND,
    confidence=Confidence.MEDIUM,
    location=ref.location,
    url=ref.url,
    method=ref.method,
    parameter=ref.param,
    id_type=ref.id_type,
    original_value=ref.value,
    tampered_value=tampered_value,
    baseline_status=baseline.status,
    tampered_status=tamper_fp.status,
    baseline_length=baseline.body_length,
    tampered_length=tamper_fp.body_length,
    owner_fields_leaked=[],
    evidence_snippet=tamper_fp.body[:500],
    notes=(
      f"blind IDOR: status {baseline.status} → {tamper_fp.status} "
      f"with no response body; side-effect may have occurred. {description}"
    ),
  )


# ---------------------------------------------------------------------------
# curl reproduction command builder
# ---------------------------------------------------------------------------

def _build_curl_command(
  url:     str,
  method:  str,
  headers: Dict[str, str],
  body:    str,
) -> str:
  """Build a curl command string for reproducing a finding."""
  import shlex
  parts = ["curl", "-s", "-X", method]
  for k, v in headers.items():
    if k.lower() in ('host', 'content-length'):
      continue
    parts += ["-H", f"{k}: {v}"]
  if body:
    parts += ["--data-raw", body]
  parts.append(url)
  return " ".join(shlex.quote(p) for p in parts)


# ---------------------------------------------------------------------------
# Shared single-request helper (used by mass-assignment + soft-delete)
# ---------------------------------------------------------------------------
def _do_single_request(
  url:        str,
  method:     str,
  headers:    Dict[str, str],
  body:       str,
  proxy:      str,
  timeout:    int,
  verify_ssl: bool,
  delay:      float,
) -> Optional[ResponseFingerprint]:
  from .tamper import _do_request as _tamper_do_request
  if delay > 0:
    time.sleep(delay)
  return _tamper_do_request(
    url=url,
    method=method,
    headers=headers,
    body=body,
    proxy=proxy,
    timeout=timeout,
    verify_ssl=verify_ssl,
    _retries=0,
  )