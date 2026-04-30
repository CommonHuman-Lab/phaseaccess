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
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .reporter import (
  IDORFinding, IDORType, IDORLocation, Confidence, ScanResult,
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

  # Scan breadth
  threads:          int = 5
  max_candidates:   int = 10           # tamper candidates per parameter
  method_bypass:    bool = True        # test HTTP method bypass
  param_pollution:  bool = True        # test HPP

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

  # Harvested IDs from session_a responses (for ID chaining)
  harvested_pool: Dict[str, List[str]] = {}

  with concurrent.futures.ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futures = {
      pool.submit(
        _scan_endpoint,
        url, opts, session_pair, harvested_pool, log,
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
        # Merge harvested IDs
        for k, vals in ep_result.harvested_ids.items():
          harvested_pool.setdefault(k, []).extend(vals)
      except Exception as e:
        result.errors.append(f"Endpoint {url} failed: {e}")

  result.harvested_ids = harvested_pool
  result.id_types_found = list({
    f.id_type for f in result.findings
  })

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
        )
        partial.findings.append(finding)
        log(
          f"[+] {diff.confidence.upper()} {idor_type} — "
          f"{ref.param}={cand.value!r} @ {url}"
        )
        # Stop on first confirmed finding for this ref to avoid noise
        if diff.verdict == DiffVerdict.CONFIRMED:
          break

    # 4. Method bypass check
    if opts.method_bypass:
      method_results = send_method_variants(
        ref=ref,
        extra_headers=pair.headers_for('b') if pair.is_dual else pair.headers_for('a'),
        cookies=pair.cookies_for('b') if pair.is_dual else pair.cookies_for('a'),
        proxy=opts.proxy,
        timeout=opts.timeout,
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
            notes="HTTP parameter pollution",
          ))

  return partial


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_session_pair(opts: ScanOptions) -> SessionPair:
  from .session import Session, SessionPair
  session_a = Session(
    label=opts.session_a_label,
    headers=opts.session_a_headers,
    cookies=opts.session_a_cookies,
  )
  session_b: Optional[SessionPair] = None
  if opts.session_b_label:
    from .session import Session as _S
    session_b = _S(
      label=opts.session_b_label,
      headers=opts.session_b_headers,
      cookies=opts.session_b_cookies,
    )
  return SessionPair(session_a=session_a, session_b=session_b)


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
