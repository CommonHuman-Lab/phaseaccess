# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/chainer.py
Multi-step stored IDOR detection.

Flow:
  1. Session_a creates a resource via a POST (--chain-create).
  2. IDs are harvested from the response.
  3. Session_b tries to access/read those IDs via the read URL template
     (--chain-read, e.g. /api/items/{id}).
  4. If session_b gets 200 and the response contains session_a's ownership
     fields → CONFIRMED horizontal IDOR finding.
"""

from __future__ import annotations

import logging
import re
import time
import urllib.parse as up
from typing import Callable, Dict, List, Optional

from .reporter import (
    Confidence, IDORFinding, IDORLocation, IDORType, IDType, ScanResult,
)
from .fingerprint import build_baseline, fingerprint_response
from .extractor import harvest_ids_from_response
from .session import SessionPair
from .tamper import fire_request

logger = logging.getLogger(__name__)

# Regex to find {placeholder} in read URL template
_RE_PLACEHOLDER = re.compile(r'\{([^}]+)\}')


def chain_scan(
    create_url:       str,
    create_method:    str,
    create_body:      str,
    read_url_template: str,
    opts,             # ScanOptions — avoid circular import
    pair:             SessionPair,
    log:              Callable[[str], None],
) -> List[IDORFinding]:
    """Test stored / multi-step IDOR: session_a creates, session_b reads.

    Parameters
    ----------
    create_url:
        Endpoint that creates a resource when called with session_a.
    create_method:
        HTTP method for the create call (usually POST or PUT).
    create_body:
        Request body for the create call.
    read_url_template:
        URL template with ``{id}`` (or ``{<field_name>}``) placeholders,
        e.g. ``/api/items/{id}`` or ``http://target.com/users/{user_id}``.
    opts:
        ScanOptions instance (imported lazily to avoid circular imports).
    pair:
        SessionPair carrying session_a and session_b credentials.
    log:
        Logging callback (same as used by the scanner).
    """
    findings: List[IDORFinding] = []

    if not pair.is_dual:
        log("[!] chain_scan: requires dual-session mode (--label-b)")
        return findings

    # Step 1 — session_a creates a resource
    log(f"[~] chain_scan: session_a creating resource via {create_method} {create_url}")
    a_headers = dict(pair.headers_for('a'))
    a_cookies = pair.cookies_for('a')
    if a_cookies:
        a_headers.setdefault('Cookie', a_cookies)

    if opts.delay > 0:
        time.sleep(opts.delay)

    create_fp = fire_request(
        url=create_url,
        method=create_method.upper(),
        headers=a_headers,
        body=create_body,
        proxy=opts.proxy,
        timeout=opts.timeout,
        verify_ssl=opts.verify_ssl,
        _retries=1,
    )
    if create_fp is None:
        log(f"[!] chain_scan: create request failed ({create_url})")
        return findings

    if create_fp.status not in (200, 201, 202):
        log(f"[~] chain_scan: create returned {create_fp.status} — no resource to probe")
        return findings

    # Step 2 — harvest IDs from the create response
    harvested = harvest_ids_from_response(create_url, create_fp.body)
    if not harvested:
        log("[~] chain_scan: no IDs found in create response")
        return findings

    log(f"[~] chain_scan: harvested {len(harvested)} ID(s) from create response")

    # Step 3 — also capture session_a's ownership fields from the response
    a_ownership = create_fp.ownership_values

    # Step 4 — session_b probes each harvested ID via the read template
    placeholders = _RE_PLACEHOLDER.findall(read_url_template)

    for h in harvested:
        # Match placeholder to field name (exact or substring)
        matched_placeholder = _match_placeholder(h.field, placeholders)
        if not matched_placeholder and placeholders:
            matched_placeholder = placeholders[0]   # fall back to first placeholder
        if not matched_placeholder:
            continue

        read_url = _fill_template(read_url_template, matched_placeholder, h.value)

        # Make read_url absolute if needed
        if not read_url.startswith(("http://", "https://")):
            parsed_create = up.urlparse(create_url)
            base = f"{parsed_create.scheme}://{parsed_create.netloc}"
            read_url = base + read_url

        log(f"[~] chain_scan: session_b probing {read_url}")

        b_headers = dict(pair.headers_for('b'))
        b_cookies = pair.cookies_for('b')
        if b_cookies:
            b_headers.setdefault('Cookie', b_cookies)

        if opts.delay > 0:
            time.sleep(opts.delay)

        b_fp = fire_request(
            url=read_url,
            method="GET",
            headers=b_headers,
            body="",
            proxy=opts.proxy,
            timeout=opts.timeout,
            verify_ssl=opts.verify_ssl,
            _retries=1,
            baseline_body=create_fp.body,
        )
        if b_fp is None:
            continue

        if b_fp.status != 200:
            log(f"[~] chain_scan: session_b got {b_fp.status} on {read_url} — access denied")
            continue

        # Step 5 — check session_b's response for session_a's ownership fields
        leaked = [
            key for key, val in a_ownership.items()
            if len(val) >= 6 and val in b_fp.body
        ]

        confidence = Confidence.CONFIRMED if leaked else Confidence.HIGH

        finding = IDORFinding(
            idor_type=IDORType.HORIZONTAL,
            confidence=confidence,
            location=IDORLocation.PATH_SEGMENT,
            url=read_url,
            method="GET",
            parameter=matched_placeholder,
            id_type=IDType.UNKNOWN,
            original_value=h.value,
            tampered_value=h.value,
            baseline_status=create_fp.status,
            tampered_status=b_fp.status,
            baseline_length=create_fp.body_length,
            tampered_length=b_fp.body_length,
            owner_fields_leaked=leaked,
            evidence_snippet=b_fp.body[:500],
            session_a_label=opts.session_a_label,
            session_b_label=opts.session_b_label,
            notes=(
                f"stored IDOR: session_a created resource (ID={h.value!r}), "
                f"session_b accessed it via {read_url}"
                + (f"; ownership confirmed: {', '.join(leaked)}" if leaked else "")
            ),
        )
        findings.append(finding)
        log(
            f"[+] {confidence.upper()} stored IDOR — "
            f"session_b read session_a's resource at {read_url}"
        )

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _match_placeholder(field_name: str, placeholders: List[str]) -> Optional[str]:
    """Return the placeholder whose name best matches field_name."""
    field_lower = field_name.lower()
    for ph in placeholders:
        if ph.lower() == field_lower:
            return ph
    for ph in placeholders:
        if ph.lower() in field_lower or field_lower in ph.lower():
            return ph
    return None


def _fill_template(template: str, placeholder: str, value: str) -> str:
    """Replace ``{placeholder}`` in template with value."""
    return template.replace("{" + placeholder + "}", value)
