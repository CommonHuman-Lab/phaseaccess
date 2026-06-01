# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Translate a GloomProxy ScanContext into PhaseAccess ScanOptions.

PhaseAccess needs at least one authenticated session (session_a).
An optional second session (session_b) enables cross-role IDOR detection.

Auth injection strategy:
  - Primary auth snapshot (ctx.config["auth"]) → session_a headers/cookies
  - ctx.config["session_b"] (optional raw auth dict) → session_b headers/cookies
"""
from __future__ import annotations

from gloomproxy_sdk import ScanContext
from gloomproxy_sdk.auth import AuthSnapshot, extract_auth

from phaseaccess.engine.scanner import ScanOptions


def _auth_to_headers_and_cookies(auth: AuthSnapshot) -> tuple[dict[str, str], str]:
    headers = auth.merged_headers()
    cookies = auth.cookie_header
    return headers, cookies


def build_options(ctx: ScanContext) -> ScanOptions:
    """Build PhaseAccess ScanOptions from a GloomProxy ScanContext."""
    cfg = ctx.config

    # Session A — primary auth
    auth_a = extract_auth(cfg)
    headers_a, cookies_a = _auth_to_headers_and_cookies(auth_a)

    # Session B — optional second role (for privilege-escalation IDOR checks)
    session_b_raw = cfg.get("session_b", {})
    auth_b = AuthSnapshot.from_dict(session_b_raw) if session_b_raw else None
    headers_b, cookies_b = _auth_to_headers_and_cookies(auth_b) if auth_b else ({}, "")

    extra_urls: list[str] = list(cfg.get("endpoints", []))

    return ScanOptions(
        session_a_headers=headers_a,
        session_a_cookies=cookies_a,
        session_a_label=str(cfg.get("session_a_label", "session_a")),
        session_b_headers=headers_b,
        session_b_cookies=cookies_b,
        session_b_label=str(cfg.get("session_b_label", "session_b")),
        extra_urls=extra_urls,
        timeout=int(cfg.get("timeout", 30)),
        threads=int(cfg.get("threads", 5)),
        proxy=str(cfg.get("proxy", "")),
    )
