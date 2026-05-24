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
import re
import threading
import time
import urllib.parse as _up
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

from .reporter import (
  IDORFinding, IDORType, IDORLocation, Confidence, IDType, ScanResult,
  CONFIDENCE_RANK,
)
from .extractor import (
  ObjectRef, extract_all, harvest_ids_from_response,
)
from .id_engine import generate_candidates, detect_id_type
from .fingerprint import build_baseline, ResponseFingerprint
from .tamper import send_tampered, send_method_variants, send_param_pollution, fire_request
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

  # Form endpoints discovered by the crawler (each carries its own method + body)
  form_scan_targets: List["FormScanTarget"] = field(default_factory=list)

  # Per-path-prefix auth header overrides populated by --auto-login
  url_auth_overrides_a: Dict[str, Dict[str, str]] = field(default_factory=dict)
  url_auth_overrides_b: Dict[str, Dict[str, str]] = field(default_factory=dict)

  # Callback for live progress
  on_log: Optional[Callable[[str], None]] = None


@dataclass
class FormScanTarget:
  """A form-based endpoint discovered by the crawler with its own method and body."""
  url:    str
  method: str = "POST"
  body:   str = ""  # URL-encoded or JSON body


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

  # Build per-target list, applying URL-specific auth and method/body overrides
  _all_targets: List[tuple] = []
  for _u in [target] + (opts.extra_urls or []):
    _t_opts = _apply_url_opts(_u, opts)
    _t_pair = session_pair if _t_opts is opts else _build_session_pair(_t_opts)
    _all_targets.append((_u, _t_opts, _t_pair))
  for _ft in (opts.form_scan_targets or []):
    _t_opts = _apply_url_opts(_ft.url, opts, method=_ft.method, body=_ft.body)
    _t_pair = session_pair if _t_opts is opts else _build_session_pair(_t_opts)
    _all_targets.append((_ft.url, _t_opts, _t_pair))

  log(f"[*] PhaseAccess starting — {len(_all_targets)} endpoint(s)")
  log(f"[*] Mode: {'dual-session' if session_pair.is_dual else 'single-session'}")
  if not opts.verify_ssl:
    log("[!] SSL certificate verification disabled (--insecure)")

  # Pre-compute session B's own identity values so we can exclude them from
  # cross-session CONFIRMED verdicts.  Without this, the check fires a false
  # positive whenever session B happens to be the resource owner at session A's
  # URL (e.g. patient.john at /patients/1 — B's own record, not an IDOR).
  #
  # We probe a handful of well-known "own" paths; the first few that return 200
  # with extractable ownership values are enough.
  session_b_identity: Dict[str, str] = {}
  if session_pair.is_dual:
    import urllib.parse as _up2
    _parsed_target = _up2.urlparse(target)
    _origin = f"{_parsed_target.scheme}://{_parsed_target.netloc}"
    _own_paths = ["", "/", "/dashboard", "/profile", "/me", "/account", "/home"]
    for _own_path in _own_paths:
      _own_url = _origin + _own_path
      _own_fp = build_baseline(
        url=_own_url,
        method="GET",
        headers=session_pair.headers_for("b"),
        cookies=session_pair.cookies_for("b"),
        proxy=opts.proxy,
        timeout=opts.timeout,
        verify_ssl=opts.verify_ssl,
        repeats=1,
      )
      if _own_fp and _own_fp.status == 200 and _own_fp.ownership_values:
        session_b_identity.update(_own_fp.ownership_values)
        if len(session_b_identity) >= 3:
          break
    if session_b_identity:
      log(f"[*] Session B identity harvested: {list(session_b_identity.keys())}")

  # Harvested IDs from session_a responses (for ID chaining)
  harvested_pool: Dict[str, List[str]] = {}
  harvested_lock = threading.Lock()

  with concurrent.futures.ThreadPoolExecutor(max_workers=opts.threads) as pool:
    futures = {
      pool.submit(
        _scan_endpoint,
        _url, _t_opts, _t_pair, harvested_pool, harvested_lock, log,
        session_b_identity,
      ): _url
      for _url, _t_opts, _t_pair in _all_targets
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
  url:               str,
  opts:              ScanOptions,
  pair:              SessionPair,
  harvested_pool:    Dict[str, List[str]],
  harvested_lock:    threading.Lock,
  log:               Callable[[str], None],
  session_b_identity: Optional[Dict[str, str]] = None,
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
    return partial

  partial.requests_sent += 1

  # Harvest IDs from baseline response (for chaining)
  harvested = harvest_ids_from_response(url, baseline.body)
  for h in harvested:
    partial.harvested_ids.setdefault(h.field, []).append(h.value)

  # 2. Extract object refs
  refs = extract_all(url, opts.method, opts.body, pair.headers_for('a'))

  # Error-driven param discovery: 400/422 → extract required field names and retry once
  if baseline.status in (400, 422) and not refs:
    for _epname, _epval in _extract_error_params(baseline.body):
      if opts.method.upper() in ("GET", "HEAD", "DELETE"):
        _ep_url = _url_append_param(url, _epname, str(_epval))
        _ep_retry = build_baseline(
          url=_ep_url, method=opts.method, headers=pair.headers_for('a'),
          body=opts.body, cookies=pair.cookies_for('a'), proxy=opts.proxy,
          timeout=opts.timeout, verify_ssl=opts.verify_ssl, delay=opts.delay,
        )
        partial.requests_sent += 1
        if _ep_retry and _ep_retry.status == 200:
          url = _ep_url
          baseline = _ep_retry
          refs = extract_all(url, opts.method, opts.body, pair.headers_for('a'))
          log(f"[~] Error-driven discovery: retrying with ?{_epname}={_epval} → 200")
          break
      else:
        try:
          _ep_bd: dict = _json.loads(opts.body) if opts.body else {}
        except Exception:
          _ep_bd = {}
        if _epname not in _ep_bd:
          _ep_bd[_epname] = _epval
          _ep_body = _json.dumps(_ep_bd)
          _ep_retry = build_baseline(
            url=url, method=opts.method,
            headers={**pair.headers_for('a'), 'Content-Type': 'application/json'},
            body=_ep_body, cookies=pair.cookies_for('a'), proxy=opts.proxy,
            timeout=opts.timeout, verify_ssl=opts.verify_ssl, delay=opts.delay,
          )
          partial.requests_sent += 1
          if _ep_retry and _ep_retry.status == 200:
            baseline = _ep_retry
            opts = _apply_url_opts(url, opts, body=_ep_body)
            refs = extract_all(url, opts.method, opts.body, pair.headers_for('a'))
            log(f"[~] Error-driven discovery: POST body {_ep_body[:60]} → 200")
            break

  # Dual-session cross-session check — deliberately placed BEFORE the no-refs early
  # return so that endpoints with no extractable params (e.g. /user/settings) are
  # still checked for direct ownership-field leakage across sessions.
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
      # Direct access: session_b requests session_a's URL with session_a's ownership data visible
      cross_finding = _check_direct_cross_session(
        url, baseline, b_baseline, opts, session_b_identity or {}
      )
      if cross_finding:
        partial.findings.append(cross_finding)
        log(f"[+] {cross_finding.confidence} {cross_finding.idor_type} — cross-session @ {url}")

  if not refs:
    log(f"[~] No object references found in {url}")
    return partial

  partial.endpoints_tested = 1
  log(f"[~] Found {len(refs)} object ref(s) in {url}")

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
      url=ref.url,
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
        is_dual=pair.is_dual,
      )

      if diff.verdict in (DiffVerdict.CONFIRMED, DiffVerdict.LIKELY, DiffVerdict.POSSIBLE):
        idor_type = _classify_idor_type(
          ref, cand.is_foreign, pair.is_dual, diff.verdict
        )
        confidence = diff.confidence
        # In dual-session mode, ownership field leakage is cross-user confirmed
        if pair.is_dual and diff.leaked_fields and diff.verdict in (DiffVerdict.CONFIRMED, DiffVerdict.LIKELY):
          confidence = Confidence.CONFIRMED
        finding = _make_finding(
          idor_type=idor_type,
          confidence=confidence,
          location=ref.location,
          url=url,
          method=opts.method,
          parameter=ref.param,
          id_type=ref.id_type,
          original_value=ref.value,
          tampered_value=cand.value,
          baseline=baseline,
          tampered_fp=tamper_result.fingerprint,
          diff_result=diff,
          notes="; ".join(diff.signals[:5]),
          session_a_label=opts.session_a_label,
          session_b_label=opts.session_b_label,
          curl_command=_build_curl_command(
            tamper_result.effective_url,
            opts.method,
            tamper_result.effective_headers or {},
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
      _run_method_bypass(ref, baseline, known_foreign, url, opts, pair, partial)

    # 5. Param pollution
    if opts.param_pollution and ref.location == IDORLocation.QUERY_PARAM and candidates:
      _run_param_pollution(ref, baseline, known_foreign, url, opts, pair, partial, candidates)

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
# Method bypass + param pollution sub-checks (extracted from _scan_endpoint)
# ---------------------------------------------------------------------------

def _run_method_bypass(
  ref:          ObjectRef,
  baseline:     ResponseFingerprint,
  known_foreign: Dict[str, str],
  url:          str,
  opts:         ScanOptions,
  pair:         SessionPair,
  partial:      ScanResult,
) -> None:
  """Fire all alternative HTTP methods and record any method-bypass findings."""
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
    diff = compare(baseline, mr.fingerprint, known_foreign or None, is_dual=pair.is_dual)
    if diff.verdict in (DiffVerdict.CONFIRMED, DiffVerdict.LIKELY):
      partial.findings.append(_make_finding(
        idor_type=IDORType.METHOD_BYPASS,
        confidence=diff.confidence,
        location=ref.location,
        url=url,
        method=mr.ref.method,
        parameter=ref.param,
        id_type=ref.id_type,
        original_value=ref.value,
        tampered_value=ref.value,
        baseline=baseline,
        tampered_fp=mr.fingerprint,
        diff_result=diff,
        notes=f"method bypass via {mr.ref.method}",
        session_a_label=opts.session_a_label,
        session_b_label=opts.session_b_label,
      ))


def _run_param_pollution(
  ref:          ObjectRef,
  baseline:     ResponseFingerprint,
  known_foreign: Dict[str, str],
  url:          str,
  opts:         ScanOptions,
  pair:         SessionPair,
  partial:      ScanResult,
  candidates:   list,
) -> None:
  """Attempt HTTP parameter pollution with the first candidate and record findings."""
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
    diff = compare(baseline, pp_result.fingerprint, known_foreign or None, is_dual=pair.is_dual)
    if diff.verdict in (DiffVerdict.CONFIRMED, DiffVerdict.LIKELY):
      partial.findings.append(_make_finding(
        idor_type=IDORType.PARAM_POLLUTION,
        confidence=diff.confidence,
        location=ref.location,
        url=url,
        method=opts.method,
        parameter=ref.param,
        id_type=ref.id_type,
        original_value=ref.value,
        tampered_value=candidates[0].value,
        baseline=baseline,
        tampered_fp=pp_result.fingerprint,
        diff_result=diff,
        notes="HTTP parameter pollution",
        session_a_label=opts.session_a_label,
        session_b_label=opts.session_b_label,
      ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_session_pair(opts: ScanOptions) -> SessionPair:
  from .session import Session
  from commonhuman_core.http import random_ua
  raw_ua = opts.user_agent or "random"
  ua = random_ua() if raw_ua.lower() == "random" else raw_ua

  def _apply_headers(base: Dict[str, str]) -> Dict[str, str]:
    h = dict(base)
    h.setdefault('User-Agent', ua)
    h.setdefault('Accept', 'application/json, */*;q=0.9')
    h.setdefault('Accept-Language', 'en-US,en;q=0.9')
    return h

  session_a = Session(
    label=opts.session_a_label,
    headers=_apply_headers(opts.session_a_headers),
    cookies=opts.session_a_cookies,
  )
  session_b: Optional[Session] = None
  if opts.session_b_label:
    session_b = Session(
      label=opts.session_b_label,
      headers=_apply_headers(opts.session_b_headers),
      cookies=opts.session_b_cookies,
    )
  return SessionPair(session_a=session_a, session_b=session_b)


def _find_override(url: str, overrides: Dict[str, Dict[str, str]]) -> Dict[str, str]:
  """Return headers from the longest matching path-prefix key in overrides, or {}."""
  path = _up.urlparse(url).path
  best_len, best = 0, {}
  for prefix, hdrs in overrides.items():
    if path.startswith(prefix) and len(prefix) > best_len:
      best_len, best = len(prefix), hdrs
  return best


def _apply_url_opts(
  url:    str,
  opts:   ScanOptions,
  method: Optional[str] = None,
  body:   Optional[str] = None,
) -> ScanOptions:
  """Return a copy of opts with URL-specific overrides applied, or opts itself if none."""
  import copy as _copy
  ov_a = _find_override(url, opts.url_auth_overrides_a)
  ov_b = _find_override(url, opts.url_auth_overrides_b)
  if not ov_a and not ov_b and not method and body is None:
    return opts
  new = _copy.copy(opts)
  if ov_a:
    new.session_a_headers = {**opts.session_a_headers, **ov_a}
  if ov_b:
    new.session_b_headers = {**opts.session_b_headers, **ov_b}
  if method:
    new.method = method
  if body is not None:
    new.body = body
  return new


def _extract_error_params(body: str) -> list:
  """
  Parse a 400/422 response body for required field names.
  Handles:
    {"error": "report_id (integer) required"}
    {"detail": [{"loc": ["body", "resource_id"], "msg": "field required"}]}
  Returns list of (field_name, probe_value) tuples.
  """
  import re as _re_ep
  _FIELD_TYPE_RE = _re_ep.compile(
    r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\((?:integer|string|int|str|number|uuid|float)\)',
    _re_ep.I,
  )
  _BLACKLIST = frozenset({"true", "false", "null", "error", "msg", "message", "detail"})

  results: list = []
  seen: set = set()

  def _add(name: str, val: object = 1) -> None:
    if name not in seen and name.lower() not in _BLACKLIST and len(name) > 1:
      seen.add(name)
      results.append((name, val))

  try:
    data = _json.loads(body)
    detail = data.get("detail")
    if isinstance(detail, list):
      for item in detail:
        if isinstance(item, dict):
          loc = item.get("loc", [])
          if loc:
            fname = str(loc[-1])
            if fname not in ("body", "query", "path"):
              _add(fname)
      if results:
        return results
    for key in ("error", "message", "msg", "description", "errors"):
      v = data.get(key)
      if isinstance(v, str):
        for m in _FIELD_TYPE_RE.finditer(v):
          _add(m.group(1))
        if results:
          return results
  except Exception:
    pass

  for m in _FIELD_TYPE_RE.finditer(body):
    _add(m.group(1))
  return results


def _url_append_param(url: str, param: str, value: str) -> str:
  """Append ?param=value to a URL, preserving existing query params."""
  p = _up.urlparse(url)
  qs = _up.parse_qsl(p.query, keep_blank_values=True)
  qs.append((param, value))
  return _up.urlunparse(p._replace(query=_up.urlencode(qs)))


_NUMERIC_SEG_RE = re.compile(r'/\d+(?=/|$)')

def _url_template(url: str) -> str:
  """Replace numeric path segments with {id} for deduplication."""
  parsed = _up.urlparse(url)
  path = _NUMERIC_SEG_RE.sub('/{id}', parsed.path)
  return _up.urlunparse(parsed._replace(path=path, query=''))


def _deduplicate_findings(findings: List[IDORFinding]) -> List[IDORFinding]:
  """
  Keep only the highest-confidence finding per (url_template, parameter, idor_type).
  URL templates collapse numeric segments so /admin/users/1 and /admin/users/2
  are treated as the same finding.
  """
  def _rank(c: str) -> int:
    return CONFIDENCE_RANK.get(c, len(CONFIDENCE_RANK))

  best: Dict[tuple, IDORFinding] = {}
  for f in findings:
    key = (_url_template(f.url), f.parameter, f.idor_type)
    existing = best.get(key)
    if existing is None or _rank(f.confidence) < _rank(existing.confidence):
      best[key] = f

  seen: set = set()
  result: List[IDORFinding] = []
  for f in findings:
    key = (_url_template(f.url), f.parameter, f.idor_type)
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
  """
  Classify the IDOR type based on session mode and candidate origin.

  - Dual-session + foreign ID   → HORIZONTAL (peer access: attacker reaches owner's resource)
  - Dual-session + non-foreign  → HORIZONTAL (both sessions got 200 — lateral, not privilege)
  - Single-session + any        → HORIZONTAL (default: lateral access assumption)

  Note: VERTICAL is assigned explicitly by _check_direct_cross_session() when it
  detects a 200-vs-4xx privilege gate between the two sessions.  Tamper-candidate
  findings always return HORIZONTAL because the 200→4xx path is suppressed in
  _verdict() before a finding is ever created.
  """
  return IDORType.HORIZONTAL


# ---------------------------------------------------------------------------
# IDORFinding factory — reduces constructor duplication across scanner checks
# ---------------------------------------------------------------------------

def _make_finding(
  *,
  idor_type:       IDORType,
  confidence:      Confidence,
  location:        IDORLocation,
  url:             str,
  method:          str,
  parameter:       str,
  id_type:         IDType,
  original_value:  str,
  tampered_value:  str,
  baseline:        ResponseFingerprint,
  tampered_fp:     ResponseFingerprint,
  diff_result:     Any = None,
  evidence_snippet: str = "",
  notes:           str = "",
  session_a_label: str = "",
  session_b_label: str = "",
  curl_command:    str = "",
) -> IDORFinding:
  """Construct an IDORFinding with all common fields pre-filled."""
  leaked = diff_result.leaked_fields if diff_result is not None else []
  snippet = (diff_result.evidence_snippet if diff_result is not None else evidence_snippet) or evidence_snippet
  return IDORFinding(
    idor_type=idor_type,
    confidence=confidence,
    location=location,
    url=url,
    method=method,
    parameter=parameter,
    id_type=id_type,
    original_value=original_value,
    tampered_value=tampered_value,
    baseline_status=baseline.status,
    tampered_status=tampered_fp.status,
    baseline_length=baseline.body_length,
    tampered_length=tampered_fp.body_length,
    owner_fields_leaked=leaked,
    evidence_snippet=snippet,
    session_a_label=session_a_label,
    session_b_label=session_b_label,
    notes=notes,
    curl_command=curl_command,
  )




# ---------------------------------------------------------------------------
# Direct cross-session access check
# ---------------------------------------------------------------------------

def _check_direct_cross_session(
  url:                str,
  a_baseline:         ResponseFingerprint,
  b_baseline:         ResponseFingerprint,
  opts:               ScanOptions,
  session_b_identity: Dict[str, str] = {},
) -> Optional[IDORFinding]:
  """
  Cross-session checks on session_a's URL:

  1. Horizontal IDOR (both 200): session_b sees session_a's ownership fields.
  2. Vertical IDOR (A=200, B=403/401): session_b is blocked — flag as HIGH so
     the analyst knows this endpoint is access-controlled and can focus further
     testing on it (e.g. JWT tampering, method bypass).
  """
  refs = extract_all(url, opts.method)
  first_ref = refs[0] if refs else None

  # Case 1: horizontal IDOR — both sessions get 200, B sees A's ownership data.
  # Values that belong to session B's own identity are excluded — if B is the
  # legitimate owner of a resource (e.g. /resource/1 belongs to user B), those
  # values appearing in B's response are not evidence of cross-user leakage.
  if a_baseline.status == 200 and b_baseline.status == 200:
    b_own_values = set(session_b_identity.values())
    leaked = [
      key for key, val in a_baseline.ownership_values.items()
      if len(val) >= 8 and val in b_baseline.body and val not in b_own_values
    ]
    if not leaked:
      return None
    return IDORFinding(
      idor_type=IDORType.HORIZONTAL,
      confidence=Confidence.CONFIRMED,
      location=first_ref.location if first_ref else IDORLocation.PATH_SEGMENT,
      url=url,
      method=opts.method,
      parameter=first_ref.param if first_ref else "[direct]",
      id_type=first_ref.id_type if first_ref else IDType.UNKNOWN,
      original_value=first_ref.value if first_ref else "",
      tampered_value=first_ref.value if first_ref else "",
      baseline_status=a_baseline.status,
      tampered_status=b_baseline.status,
      baseline_length=a_baseline.body_length,
      tampered_length=b_baseline.body_length,
      owner_fields_leaked=leaked,
      evidence_snippet=b_baseline.body[:500],
      session_a_label=opts.session_a_label,
      session_b_label=opts.session_b_label,
      notes=(
        f"session_b directly accessed session_a's resource; "
        f"ownership fields confirmed: {', '.join(leaked)}"
      ),
    )

  # Case 2: vertical access-control gate — A gets 200, B gets 4xx.
  # Not an IDOR in itself (access is correctly denied), but a HIGH signal that
  # the endpoint is privilege-gated, worth targeted follow-up testing.
  if a_baseline.status == 200 and b_baseline.status in (401, 403):
    return IDORFinding(
      idor_type=IDORType.VERTICAL,
      confidence=Confidence.HIGH,
      location=first_ref.location if first_ref else IDORLocation.PATH_SEGMENT,
      url=url,
      method=opts.method,
      parameter=first_ref.param if first_ref else "[direct]",
      id_type=first_ref.id_type if first_ref else IDType.UNKNOWN,
      original_value=first_ref.value if first_ref else "",
      tampered_value=first_ref.value if first_ref else "",
      baseline_status=a_baseline.status,
      tampered_status=b_baseline.status,
      baseline_length=a_baseline.body_length,
      tampered_length=b_baseline.body_length,
      owner_fields_leaked=[],
      evidence_snippet=a_baseline.body[:200],
      session_a_label=opts.session_a_label,
      session_b_label=opts.session_b_label,
      notes=(
        f"{opts.session_a_label} can access this endpoint (200); "
        f"{opts.session_b_label} is blocked ({b_baseline.status}) — "
        f"privilege-gated endpoint confirmed"
      ),
    )

  return None


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
    injected = {k: v[0] for k, v in _up.parse_qs(
        ref.body_context, keep_blank_values=True).items()}
  else:
    injected = {}

  # Add all ownership field candidates with the foreign ID
  for f in _MA_FIELDS:
    injected[f] = foreign_id

  body_str = _json.dumps(injected)

  # Use session_b (attacker) in dual-session mode; fall back to session_a
  req_headers = dict(pair.headers_for('b') if pair.is_dual else pair.headers_for('a'))
  req_headers.setdefault('Content-Type', 'application/json')
  cookies = pair.cookies_for('b') if pair.is_dual else pair.cookies_for('a')
  if cookies:
    req_headers.setdefault('Cookie', cookies)

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

  notes = "mass assignment: injected ownership field accepted" + (
    "; injected value reflected in response" if injected_reflected else ""
  )

  # Follow-up GET with session_a — confirm ownership actually changed
  if pair.is_dual:
    a_headers = dict(pair.headers_for('a'))
    a_cookies = pair.cookies_for('a')
    if a_cookies:
      a_headers.setdefault('Cookie', a_cookies)
    follow_fp = _do_single_request(
      ref.url, 'GET', a_headers, "",
      opts.proxy, opts.timeout, opts.verify_ssl, opts.delay,
    )
    if follow_fp and foreign_id in follow_fp.body:
      confidence = Confidence.CONFIRMED
      notes += "; ownership change confirmed (foreign_id visible in session_a GET)"

  return _make_finding(
    idor_type=IDORType.MASS_ASSIGNMENT,
    confidence=confidence,
    location=ref.location,
    url=ref.url,
    method=ref.method,
    parameter=", ".join(_MA_FIELDS[:4]) + " ...",
    id_type=ref.id_type,
    original_value=ref.value,
    tampered_value=foreign_id,
    baseline=baseline,
    tampered_fp=fp,
    diff_result=diff,
    notes=notes,
    session_a_label=opts.session_a_label,
    session_b_label=opts.session_b_label,
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
  # Only proceed when baseline signals a potentially deleted/absent resource
  # OR when a 200 baseline might grow with deleted items included.
  if baseline.status not in (200, 404):
    return None

  # Always use session_a for soft-delete checks — the baseline was captured with
  # session_a, so growth comparisons must use the same session.  Using session_b
  # would compare two different users' pages, producing false positives.
  req_headers = dict(pair.headers_for('a'))
  cookies = pair.cookies_for('a')
  if cookies:
    req_headers.setdefault('Cookie', cookies)

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
      return _make_finding(
        idor_type=IDORType.SOFT_DELETE,
        confidence=Confidence.HIGH,
        location=IDORLocation.QUERY_PARAM,
        url=ref.url,
        method=ref.method,
        parameter=param,
        id_type=ref.id_type,
        original_value=ref.value,
        tampered_value=value,
        baseline=baseline,
        tampered_fp=fp,
        evidence_snippet=fp.body[:500],
        notes=f"soft-delete bypass: {param}={value} reveals deleted resource",
        session_a_label=opts.session_a_label,
        session_b_label=opts.session_b_label,
      )

    # Weaker signal: same-family success, body grew significantly
    if fp.status == 200 and baseline.status == 200:
      growth = (fp.body_length - baseline.body_length) / max(baseline.body_length, 1)
      if growth > 0.3 and fp.stable_hash != baseline.stable_hash:
        return _make_finding(
          idor_type=IDORType.SOFT_DELETE,
          confidence=Confidence.MEDIUM,
          location=IDORLocation.QUERY_PARAM,
          url=ref.url,
          method=ref.method,
          parameter=param,
          id_type=ref.id_type,
          original_value=ref.value,
          tampered_value=value,
          baseline=baseline,
          tampered_fp=fp,
          evidence_snippet=fp.body[:500],
          notes=f"soft-delete bypass: {param}={value} returns extra content",
          session_a_label=opts.session_a_label,
          session_b_label=opts.session_b_label,
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

  return _make_finding(
    idor_type=IDORType.BLIND,
    confidence=Confidence.MEDIUM,
    location=ref.location,
    url=ref.url,
    method=ref.method,
    parameter=ref.param,
    id_type=ref.id_type,
    original_value=ref.value,
    tampered_value=tampered_value,
    baseline=baseline,
    tampered_fp=tamper_fp,
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
  if delay > 0:
    time.sleep(delay)
  return fire_request(
    url=url,
    method=method,
    headers=headers,
    body=body,
    proxy=proxy,
    timeout=timeout,
    verify_ssl=verify_ssl,
    _retries=0,
  )