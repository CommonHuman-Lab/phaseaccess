# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — __main__.py
Standalone CLI entry point.

Options:
    -u, --url            Target URL (required)
    --crawl              Crawl target before scanning to auto-discover endpoints
    --crawl-depth        Crawler max depth (default 3)
    --crawl-pages        Crawler max pages (default 100)
    --browser-crawl      Use headless Chromium crawler for JS-rendered endpoints (requires selenium)
    --login-url          Login form URL — authenticates session A before scanning
    --login-user         Username for form login (session A)
    --login-pass         Password for form login (session A)
    --login-user-field   Username field name (default: username)
    --login-pass-field   Password field name (default: password)
    --login-url-b        Login form URL for session B
    --login-user-b       Username for session B form login
    --login-pass-b       Password for session B form login
    --auto-login         Auto-discover login endpoints during --crawl; authenticate both sessions
    --openapi            OpenAPI/Swagger spec file path or URL — imports endpoints
    --base-url           Base URL override for OpenAPI spec (overrides spec servers)
    --chain-create       Stored IDOR: session_a creates resource here (e.g. POST:/api/items)
    --chain-body         Request body for --chain-create
    --chain-read         Stored IDOR: session_b reads resource here (e.g. /api/items/{id})
    -X, --method         HTTP method (default GET)
    -d, --data           Request body (form-encoded or JSON)
    -H, --header         Header for session A: KEY:VALUE (repeatable)
    -c, --cookie         Cookie string for session A
    --label-a            Label for session A (default: session_a)
    --header-b           Header for session B: KEY:VALUE (repeatable)
    --cookie-b           Cookie string for session B
    --label-b            Label for session B (enables dual-session mode)
    --extra-url          Additional URL to test (repeatable)
    --proxy              HTTP proxy URL
    --insecure           Disable SSL certificate verification
    --delay              Seconds between requests (rate limiting)
    -t, --threads        Threads (default 5)
    --timeout            Request timeout seconds (default 15)
    --max-candidates     Tamper candidates per param (default 10)
    --no-method-bypass   Disable HTTP method bypass check
    --no-param-pollution Disable HTTP parameter pollution check
    --no-mass-assignment Disable mass assignment check
    --no-soft-delete     Disable soft-delete bypass check
    --no-blind-idor      Disable blind IDOR check
    --json               Output raw JSON
    -o, --output         Save report to file (human text or JSON with --json)
    -q, --quiet          Suppress live log output
    -v, --verbose        Enable debug logging
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from commonhuman_cli.colour import RED, GREEN, YELLOW, CYAN, BOLD, DIM
from commonhuman_cli.prompts import prompt, prompt_bool, section, safe_int
from commonhuman_cli.entrypoint import parse_headers

from phaseaccess.engine import scan, ScanOptions
from phaseaccess.engine.reporter import Confidence, CONFIDENCE_RANK

BANNER = r"""
    ____  __                    ___
   / __ \/ /_  ____ _________  /   | _____________  __________
  / /_/ / __ \/ __ `/ ___/ _ \/ /| |/ ___/ ___/ _ \/ ___/ ___/
 / ____/ / / / /_/ (__  )  __/ ___ / /__/ /__/  __(__  |__  )
/_/   /_/ /_/\__,_/____/\___/_/  |_\___/\___/\___/____/____/

  Authorization is just a suggestion.
  IDOR Detection Engine — CommonHuman-Lab
"""


def _safe_float(val: str, default: float, lo: float, hi: float) -> float:
    try:
        return max(lo, min(float(val), hi))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_url(url: str) -> str:
    url = url.strip()
    if not url:
        return "URL is required."
    if not url.startswith(("http://", "https://")):
        return "URL must start with http:// or https://"
    return ""


def _validate_extra_url(url: str) -> str:
    return _validate_url(url)


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def interactive_prompts() -> argparse.Namespace:
    print(CYAN(BANNER))
    print(DIM("  No arguments supplied — entering interactive mode."))
    print(DIM("  Press Enter to accept defaults. Ctrl+C to exit.\n"))

    section("Target")
    url = ""
    while not url:
        url = prompt("  Target URL", hint="e.g. https://api.target.com/users/42")
        err = _validate_url(url)
        if err:
            print(YELLOW(f"  [!] {err}"))
            url = ""

    method = prompt("  HTTP method", default="GET", hint="GET POST PUT PATCH DELETE")
    body = prompt("  Request body", hint="form-encoded or JSON  (blank = none)")

    section("Session A — resource owner")
    label_a = prompt("  Label", default="session_a", hint='e.g. "admin", "owner"')
    cookie_a = prompt("  Cookies", hint="name=val; name2=val2")
    token_a = prompt("  Bearer token", hint="eyJ...  (sets Authorization header)")
    headers_a: list[str] = []
    while True:
        h = prompt("  Header", hint="KEY:VALUE  (blank to finish)")
        if not h:
            break
        headers_a.append(h)
    if token_a:
        headers_a.append(f"Authorization: Bearer {token_a}")

    section("Session B — attacker  (optional, enables dual-session mode)")
    label_b = prompt("  Label", hint='e.g. "user", "attacker"  (blank = single-session)')
    cookie_b = ""
    token_b = ""
    headers_b: list[str] = []
    if label_b:
        cookie_b = prompt("  Cookies", hint="name=val; name2=val2")
        token_b = prompt("  Bearer token", hint="eyJ...")
        while True:
            h = prompt("  Header", hint="KEY:VALUE  (blank to finish)")
            if not h:
                break
            headers_b.append(h)
        if token_b:
            headers_b.append(f"Authorization: Bearer {token_b}")

    section("Extra endpoints  (optional)")
    crawl = prompt_bool("  Crawl target for additional endpoints (--crawl)", default=False)
    extra_urls: list[str] = []
    if not crawl:
        while True:
            u = prompt("  Additional URL", hint="blank to finish")
            if not u:
                break
            extra_urls.append(u)

    section("Advanced options")
    proxy = prompt("  Proxy", hint="http://127.0.0.1:8080")
    insecure = prompt_bool("  Skip SSL verification (--insecure)", default=False)
    delay_str = prompt("  Delay between requests (s)", default="0", hint="e.g. 0.5")
    threads_str = prompt("  Threads", default="5")
    timeout_str = prompt("  Timeout", default="15", hint="seconds per request")
    max_cand_str = prompt("  Candidates/param", default="10")
    method_bypass = prompt_bool("  Test method bypass", default=True)
    param_pollution = prompt_bool("  Test param pollution", default=True)
    mass_assignment = prompt_bool("  Test mass assignment", default=True)
    soft_delete = prompt_bool("  Test soft-delete bypass", default=True)
    blind_idor = prompt_bool("  Test blind IDOR", default=True)
    output = prompt("  Save report to file", hint="blank = stdout only")

    print()

    return argparse.Namespace(
        url=url,
        method=method.upper() or "GET",
        data=body,
        header=headers_a,
        cookie=cookie_a,
        label_a=label_a,
        header_b=headers_b,
        cookie_b=cookie_b,
        label_b=label_b,
        extra_url=extra_urls,
        proxy=proxy,
        insecure=insecure,
        delay=_safe_float(delay_str, 0.0, 0.0, 60.0),
        threads=safe_int(threads_str, 5, 1, 20),
        timeout=safe_int(timeout_str, 15, 5, 120),
        max_candidates=safe_int(max_cand_str, 10, 1, 50),
        no_method_bypass=not method_bypass,
        no_param_pollution=not param_pollution,
        no_mass_assignment=not mass_assignment,
        no_soft_delete=not soft_delete,
        no_blind_idor=not blind_idor,
        json_output=False,
        quiet=False,
        verbose=False,
        output=output,
        targets="",
        min_confidence="",
        user_agent="",
        crawl=crawl,
        crawl_depth=3,
        crawl_pages=100,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phaseaccess",
        description="PhaseAccess — native IDOR & BOLA scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-u", "--url", default="", help="Target URL")
    p.add_argument("--crawl", action="store_true",
                   help="Crawl target before scanning to auto-discover endpoints")
    p.add_argument("--crawl-depth", type=int, default=3, dest="crawl_depth",
                   help="Crawler max depth (default 3)")
    p.add_argument("--crawl-pages", type=int, default=100, dest="crawl_pages",
                   help="Crawler max pages (default 100)")
    p.add_argument("--browser-crawl", action="store_true", dest="browser_crawl",
                   help="Use headless Chromium for endpoint discovery (requires selenium)")
    p.add_argument("--login-url", default="", dest="login_url",
                   help="Login form URL (authenticates session A)")
    p.add_argument("--login-user", default="", dest="login_user",
                   help="Username for session A form login")
    p.add_argument("--login-pass", default="", dest="login_pass",
                   help="Password for session A form login")
    p.add_argument("--login-user-field", default="username", dest="login_user_field",
                   help="Username field name (default: username)")
    p.add_argument("--login-pass-field", default="password", dest="login_pass_field",
                   help="Password field name (default: password)")
    p.add_argument("--login-url-b", default="", dest="login_url_b",
                   help="Login form URL for session B")
    p.add_argument("--login-user-b", default="", dest="login_user_b",
                   help="Username for session B form login")
    p.add_argument("--login-pass-b", default="", dest="login_pass_b",
                   help="Password for session B form login")
    p.add_argument("--auto-login", action="store_true", dest="auto_login",
                   help="Auto-discover login endpoints during --crawl and authenticate both sessions")
    p.add_argument("--openapi", default="", dest="openapi",
                   help="OpenAPI/Swagger spec file path or URL")
    p.add_argument("--base-url", default="", dest="base_url",
                   help="Base URL override for OpenAPI spec")
    p.add_argument("--chain-create", default="", dest="chain_create",
                   help="Stored IDOR create endpoint, format METHOD:URL (e.g. POST:/api/items)")
    p.add_argument("--chain-body", default="", dest="chain_body",
                   help="Request body for --chain-create")
    p.add_argument("--chain-read", default="", dest="chain_read",
                   help="Stored IDOR read URL template (e.g. /api/items/{id})")
    p.add_argument("-X", "--method", default="GET", help="HTTP method (default GET)")
    p.add_argument("-d", "--data", default="", help="Request body")
    p.add_argument("-H", "--header", action="append", default=[], metavar="KEY:VALUE",
                   help="Session A header (repeatable)")
    p.add_argument("-c", "--cookie", default="", help="Session A cookie string")
    p.add_argument("--label-a", default="session_a", help="Label for session A")
    p.add_argument("--header-b", action="append", default=[], metavar="KEY:VALUE",
                   help="Session B header (repeatable)")
    p.add_argument("--cookie-b", default="", help="Session B cookie string")
    p.add_argument("--label-b", default="",
                   help="Session B label — enables dual-session mode")
    p.add_argument("--extra-url", action="append", default=[], metavar="URL",
                   help="Extra endpoint URL (repeatable)")
    p.add_argument("--proxy", default="", help="HTTP proxy URL")
    p.add_argument("--insecure", action="store_true",
                   help="Disable SSL certificate verification")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Seconds between requests (default 0)")
    p.add_argument("-t", "--threads", type=int, default=5,
                   help="Threads (default 5, min 1, max 50)")
    p.add_argument("--timeout", type=int, default=15,
                   help="Request timeout in seconds (default 15, min 1, max 300)")
    p.add_argument("--max-candidates", type=int, default=10)
    p.add_argument("--targets", default="",
                   help="Import targets from HAR / Burp XML / JSON file")
    p.add_argument("--min-confidence", default="", dest="min_confidence",
                   help="Minimum confidence to report: confirmed high medium low info")
    p.add_argument("--user-agent", default="", dest="user_agent",
                   help="Override User-Agent header (default: random browser UA; use 'random' to rotate)")
    p.add_argument("--no-method-bypass", action="store_true")
    p.add_argument("--no-param-pollution", action="store_true")
    p.add_argument("--no-mass-assignment", action="store_true")
    p.add_argument("--no-soft-delete", action="store_true")
    p.add_argument("--no-blind-idor", action="store_true")
    p.add_argument("--json", action="store_true", dest="json_output",
                   help="Output raw JSON")
    p.add_argument("-o", "--output", default="",
                   help="Save report to file (human text, or JSON with --json)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress live log output")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(name)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    if args.url:
        err = _validate_url(args.url)
        if err:
            print(YELLOW(f"[!] {err}"), file=sys.stderr)
            sys.exit(2)

    if args.threads < 1:
        print(YELLOW("[!] --threads must be at least 1"), file=sys.stderr)
        sys.exit(2)
    if args.threads > 50:
        print(YELLOW("[!] --threads must be at most 50"), file=sys.stderr)
        sys.exit(2)
    if args.timeout < 1:
        print(YELLOW("[!] --timeout must be at least 1 second"), file=sys.stderr)
        sys.exit(2)
    if args.timeout > 300:
        print(YELLOW("[!] --timeout must be at most 300 seconds"), file=sys.stderr)
        sys.exit(2)

    if not args.url:
        args = interactive_prompts()
    elif not args.json_output:
        print(CYAN(BANNER))

    session_a_headers = parse_headers(args.header)
    session_b_headers = parse_headers(args.header_b)

    # Form login — session A
    if getattr(args, "login_url", "") and getattr(args, "login_user", ""):
        from commonhuman_core.auth import form_login as _form_login
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Authenticating session A via {args.login_url} ..."))
        auth_a = _form_login(
            login_url=args.login_url,
            username=args.login_user,
            password=getattr(args, "login_pass", ""),
            username_field=getattr(args, "login_user_field", "username"),
            password_field=getattr(args, "login_pass_field", "password"),
        )
        if auth_a.cookies and not args.cookie:
            args.cookie = auth_a.cookies
        session_a_headers.update(auth_a.headers)
        if not args.quiet and not args.json_output:
            status = "OK" if not auth_a.is_empty() else "no credentials obtained"
            print(DIM(f"[*] Session A login: {status}"))

    # Form login — session B
    if getattr(args, "login_url_b", "") and getattr(args, "login_user_b", ""):
        from commonhuman_core.auth import form_login as _form_login
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Authenticating session B via {args.login_url_b} ..."))
        auth_b = _form_login(
            login_url=args.login_url_b,
            username=args.login_user_b,
            password=getattr(args, "login_pass_b", ""),
            username_field=getattr(args, "login_user_field", "username"),
            password_field=getattr(args, "login_pass_field", "password"),
        )
        if auth_b.cookies and not args.cookie_b:
            args.cookie_b = auth_b.cookies
        session_b_headers.update(auth_b.headers)
        # Auto-enable dual-session when session B authenticated successfully
        if (auth_b.cookies or auth_b.headers) and not args.label_b:
            args.label_b = "session_b"

    imported_extra_urls: list[str] = []
    if getattr(args, "targets", ""):
        from phaseaccess.engine.har_import import load_file as _load_import
        imported_targets = _load_import(args.targets)
        for t in imported_targets:
            u = t.get("url", "")
            if u and not _validate_extra_url(u) and u not in imported_extra_urls:
                imported_extra_urls.append(u)
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Imported {len(imported_extra_urls)} URL(s) from {args.targets}"))

    validated_extra_urls: list[str] = []
    for u in args.extra_url:
        err = _validate_extra_url(u)
        if err:
            print(YELLOW(f"[!] Extra URL {u!r} skipped: {err}"), file=sys.stderr)
        else:
            validated_extra_urls.append(u)

    combined_extra_urls = validated_extra_urls + imported_extra_urls

    # OpenAPI / Swagger spec import
    if getattr(args, "openapi", ""):
        from commonhuman_core.openapi import load_openapi as _load_openapi
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Loading OpenAPI spec from {args.openapi} ..."))
        api_endpoints = _load_openapi(args.openapi, base_url=getattr(args, "base_url", ""))
        seen_oa = {args.url} | set(combined_extra_urls)
        for ep in api_endpoints:
            if ep.url not in seen_oa and not _validate_extra_url(ep.url):
                combined_extra_urls.append(ep.url)
                seen_oa.add(ep.url)
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] OpenAPI: {len(api_endpoints)} endpoint(s) queued"))

    url_auth_overrides_a: dict = {}
    url_auth_overrides_b: dict = {}
    form_scan_targets_raw: list = []

    if getattr(args, "crawl", False) and args.url:
        import asyncio as _asyncio
        from commonhuman_core.http import AsyncHttpClient as _AsyncHttpClient
        from commonhuman_core.crawler import async_crawl as _async_crawl
        crawl_headers = {k: v for k, v in session_a_headers.items() if k.lower() != "cookie"}
        crawl_cookie = session_a_headers.get("Cookie", "") or args.cookie or ""
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Crawling {args.url} (depth={args.crawl_depth}, max={args.crawl_pages} pages) ..."))
        async def _do_crawl():
            client = _AsyncHttpClient(
                timeout=args.timeout,
                proxy=args.proxy,
                headers=crawl_headers,
                cookies=crawl_cookie,
                verify_ssl=not args.insecure,
            )
            try:
                return await _async_crawl(
                    start_url=args.url,
                    client=client,
                    max_pages=args.crawl_pages,
                    max_depth=args.crawl_depth,
                )
            finally:
                await client.aclose()
        crawl_result = _asyncio.run(_do_crawl())
        seen = {args.url} | set(combined_extra_urls)
        discovered = [u for u in crawl_result.visited_urls if u not in seen and not _validate_extra_url(u)]
        combined_extra_urls.extend(discovered)
        seen.update(discovered)

        # Mine JS string literals in page bodies for API paths the link-follower
        # can't reach (e.g. endpoints only referenced inside fetch() calls).
        import re as _re
        import urllib.parse as _up
        _js_path_re = _re.compile(
            r"""['"](/(?:[A-Za-z0-9_\-]+/){2,}[A-Za-z0-9_\-]+(?:\?[^'"<\s]*)?)['"]"""
        )
        _static_ext_re = _re.compile(r'\.(css|js|png|jpg|gif|svg|ico|woff|ttf|map)$', _re.I)
        _parsed = _up.urlparse(args.url)
        _origin = f"{_parsed.scheme}://{_parsed.netloc}"
        _js_found = 0
        for _html in crawl_result.page_sources.values():
            for _m in _js_path_re.finditer(_html):
                _path = _m.group(1)
                if _static_ext_re.search(_path.split('?')[0]):
                    continue
                _full = _origin + _path
                if _full not in seen and not _validate_extra_url(_full):
                    combined_extra_urls.append(_full)
                    seen.add(_full)
                    _js_found += 1

        # Pass 2: Template URL resolution — {id}/{oid}/{param} → probe value "1"
        _TMPL_PATH_RE = _re.compile(
            r"""['"](/(?:[A-Za-z0-9_\-]+/){1,}[A-Za-z0-9_\-]*\{[A-Za-z][A-Za-z0-9_]*\}[^"'<\s]*)['"]"""
        )
        _PLACEHOLDER_RE = _re.compile(r'\{[A-Za-z][A-Za-z0-9_]*\}')
        _tmpl_found = 0
        for _html in crawl_result.page_sources.values():
            for _tm in _TMPL_PATH_RE.finditer(_html):
                _probe_path = _PLACEHOLDER_RE.sub('1', _tm.group(1))
                _probe_full = _origin + _probe_path
                if _probe_full not in seen and not _validate_extra_url(_probe_full):
                    combined_extra_urls.append(_probe_full)
                    seen.add(_probe_full)
                    _tmpl_found += 1

        # Pass 3: Obfuscated ID reconstruction — {oid} template + literal value on same page
        _OID_TMPL_RE = _re.compile(r'/(?:[A-Za-z0-9_\-]+/){2,}[A-Za-z0-9_\-]*\{oid\}')
        _UUID_RE     = _re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', _re.I)
        _HEX32_RE    = _re.compile(r'\b[0-9a-f]{32}\b')
        _B64_RE      = _re.compile(r"'([A-Za-z0-9+/]{8,}={1,2})'")
        for _page_url, _html in crawl_result.page_sources.items():
            _oid_tmpl_m = _OID_TMPL_RE.search(_html)
            if not _oid_tmpl_m:
                continue
            _oid_tmpl = _oid_tmpl_m.group()
            _oid_vals = (
                _UUID_RE.findall(_html)
                + _HEX32_RE.findall(_html)
                + [m.group(1) for m in _B64_RE.finditer(_html)]
            )
            for _oid_val in dict.fromkeys(_oid_vals):
                if len(_oid_val) < 8:
                    continue
                _oid_url = _origin + _oid_tmpl.replace('{oid}', _oid_val)
                if _oid_url not in seen and not _validate_extra_url(_oid_url):
                    combined_extra_urls.append(_oid_url)
                    seen.add(_oid_url)
                    _tmpl_found += 1

        # Pass 4: Pollution param — reconstruct single-param baseline from duplicate-param examples
        _DUPE_PARAM_RE = _re.compile(
            r'(/[A-Za-z0-9_/\-]+\?([A-Za-z_][A-Za-z0-9_]*)=([0-9]+)(?:&\2=[0-9]+)+)'
        )
        for _html in crawl_result.page_sources.values():
            for _pm in _DUPE_PARAM_RE.finditer(_html):
                _base_path = _pm.group(1).split('?')[0]
                _pname     = _pm.group(2)
                _pvals     = _re.findall(rf'{_pname}=([0-9]+)', _pm.group(1))
                for _pv in dict.fromkeys([_pvals[0], _pvals[-1]]):
                    _clean_url = _origin + _base_path + f'?{_pname}={_pv}'
                    if _clean_url not in seen and not _validate_extra_url(_clean_url):
                        combined_extra_urls.append(_clean_url)
                        seen.add(_clean_url)
                        _tmpl_found += 1

        # Pass 5: path_param_candidates — URLs with numeric segments that returned 403/404
        _ppc_found = 0
        for _ppc in (getattr(crawl_result, 'path_param_candidates', []) or []):
            if _ppc not in seen and not _validate_extra_url(_ppc):
                combined_extra_urls.append(_ppc)
                seen.add(_ppc)
                _ppc_found += 1

        # Pass 6: Param-value hint mining — extract `param=BIG_NUM` and
        # `"param": BIG_NUM` from description pages and probe known
        # API endpoints under the same path prefix with those values.
        # Catches body-IDOR that embed the valid resource ID in
        _PVHINT_RE = _re.compile(
            r'\b([A-Za-z_][A-Za-z0-9_]{2,})["\']?\s*[=:]\s*["\']?(\d{3,})\b'
        )
        _CSS_PROPS = frozenset({
            'width', 'height', 'padding', 'margin', 'top', 'bottom', 'left',
            'right', 'size', 'weight', 'opacity', 'border', 'font', 'line',
            'min', 'max', 'gap', 'flex', 'order', 'index', 'zindex',
        })
        _pv_found = 0
        for _pg_url, _pg_html in crawl_result.page_sources.items():
            _pg_prefix = _up.urlparse(_pg_url).path
            _page_hints: dict = {}
            for _m in _PVHINT_RE.finditer(_pg_html):
                _pn = _m.group(1)
                if _pn.lower() in _CSS_PROPS:
                    continue
                _pv_val = _m.group(2)
                # Only keep if param looks like an API field, not a CSS/layout value
                if not any(kw in _pn.lower() for kw in ('id', 'num', 'key', 'ref', 'record', 'report', 'resource', 'message', 'msg', 'doc')):
                    continue
                _page_hints[_pn] = _pv_val

            if not _page_hints:
                continue

            for _pv_url in list(combined_extra_urls):
                _pv_path = _up.urlparse(_pv_url).path
                if not _pv_path.startswith(_pg_prefix):
                    continue
                _pv_existing_keys = {k for k, _ in _up.parse_qsl(_up.urlparse(_pv_url).query)}
                for _pn, _pv_val in _page_hints.items():
                    if _pn in _pv_existing_keys:
                        continue
                    _probe_url = _pv_url.split('?')[0] + f'?{_pn}={_pv_val}'
                    if _probe_url not in seen and not _validate_extra_url(_probe_url):
                        combined_extra_urls.append(_probe_url)
                        seen.add(_probe_url)
                        _pv_found += 1

        if not args.quiet and not args.json_output:
            print(DIM(
                f"[*] Crawl complete — {len(discovered)} link(s), {_js_found} JS path(s), "
                f"{_tmpl_found} template/obfusc(s), {_ppc_found} 403-candidate(s), "
                f"{_pv_found} param-hint URL(s) queued"
            ))

        # Auto-login: find login-like endpoints discovered during crawl, auth both sessions
        if getattr(args, "auto_login", False) and (args.login_user or args.login_user_b):
            import re as _re_al
            _login_re = _re_al.compile(r'/(login|auth|signin)/?$', _re_al.I)
            _user_a = args.login_user or ""
            _pass_a = getattr(args, "login_pass", "")
            _user_b = args.login_user_b or _user_a
            _pass_b = getattr(args, "login_pass_b", "") or _pass_a
            _ufield = getattr(args, "login_user_field", "username")
            _pfield = getattr(args, "login_pass_field", "password")

            def _try_login_url(lurl: str, user: str, passwd: str) -> dict:
                """Try form login then JSON POST fallback; return Authorization header dict."""
                from commonhuman_core.auth import form_login as _fl
                _r = _fl(lurl, user, passwd, username_field=_ufield, password_field=_pfield)
                if not _r.is_empty():
                    return _r.headers
                try:
                    import requests as _rq
                    _jr = _rq.post(lurl, json={_ufield: user, _pfield: passwd}, timeout=10)
                    _j = _jr.json()
                    for _k in ("token", "access_token", "accessToken", "jwt", "id_token"):
                        if _k in _j and isinstance(_j[_k], str):
                            return {"Authorization": f"Bearer {_j[_k]}"}
                except Exception:
                    pass
                return {}

            _seen_prefixes: set = set()
            for _lurl in list(crawl_result.visited_urls) + combined_extra_urls:
                _lpath = _up.urlparse(_lurl).path
                if not _login_re.search(_lpath):
                    continue
                _prefix = _lpath.rsplit("/", 1)[0]
                if _prefix in _seen_prefixes:
                    continue
                _seen_prefixes.add(_prefix)
                if not args.quiet and not args.json_output:
                    print(DIM(f"[*] Auto-login: trying {_lurl}"))
                # A short prefix (≤1 path segment) means a site-wide login —
                # apply the token globally so no manual -H flags are needed.
                _is_global = len([s for s in _prefix.split("/") if s]) <= 1
                if _user_a:
                    _ha = _try_login_url(_lurl, _user_a, _pass_a)
                    if _ha:
                        if _is_global:
                            session_a_headers.update(_ha)
                        else:
                            url_auth_overrides_a[_prefix] = _ha
                        if not args.quiet and not args.json_output:
                            _scope = "global" if _is_global else _prefix
                            print(DIM(f"[*]   Session A authenticated ({_scope})"))
                if _user_b:
                    _hb = _try_login_url(_lurl, _user_b, _pass_b)
                    if _hb:
                        if _is_global:
                            session_b_headers.update(_hb)
                        else:
                            url_auth_overrides_b[_prefix] = _hb
                        if not args.quiet and not args.json_output:
                            _scope = "global" if _is_global else _prefix
                            print(DIM(f"[*]   Session B authenticated ({_scope})"))

        form_scan_targets_raw = crawl_result.form_targets

    # Browser crawl (JS-rendered endpoint discovery)
    if getattr(args, "browser_crawl", False) and args.url:
        from commonhuman_core.browser_crawler import browser_crawl as _browser_crawl
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Browser-crawling {args.url} (headless Chromium) ..."))
        bc_cookies = args.cookie or ""
        bc_discovered = _browser_crawl(
            start_url=args.url,
            max_pages=getattr(args, "crawl_pages", 100),
            max_depth=getattr(args, "crawl_depth", 3),
            cookies=bc_cookies,
            chromium_path=getattr(args, "chromium_path", ""),
            chromedriver_path=getattr(args, "chromedriver_path", ""),
        )
        seen_bc = {args.url} | set(combined_extra_urls)
        new_bc  = [u for u in bc_discovered if u not in seen_bc and not _validate_extra_url(u)]
        combined_extra_urls.extend(new_bc)
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Browser crawl: {len(new_bc)} additional endpoint(s) queued"))

    # Convert crawler FormTarget objects to scanner FormScanTarget objects (dedup by action+method)
    from phaseaccess.engine.scanner import FormScanTarget as _FormScanTarget
    import urllib.parse as _up_form
    form_scan_targets: list = []
    _seen_form_keys: set = set()
    for _ft in form_scan_targets_raw:
        _fkey = (_ft.action, _ft.method)
        if _fkey in _seen_form_keys:
            continue
        _seen_form_keys.add(_fkey)
        _fbody = _up_form.urlencode({**_ft.base_data, **_ft.params})
        form_scan_targets.append(_FormScanTarget(url=_ft.action, method=_ft.method, body=_fbody))
    if form_scan_targets and not args.quiet and not args.json_output:
        print(DIM(f"[*] Form targets: {len(form_scan_targets)} form endpoint(s) queued"))

    def live_log(msg: str) -> None:
        if args.quiet or args.json_output:
            return
        if msg.startswith("[+]"):
            print(GREEN(msg))
        elif msg.startswith("[!]"):
            print(YELLOW(msg))
        elif msg.startswith("[~]"):
            print(CYAN(msg))
        else:
            print(DIM(msg))

    opts = ScanOptions(
        session_a_headers=session_a_headers,
        session_a_cookies=args.cookie,
        session_a_label=args.label_a,
        session_b_headers=session_b_headers,
        session_b_cookies=args.cookie_b,
        session_b_label=args.label_b,
        method=args.method.upper(),
        body=args.data,
        proxy=args.proxy,
        verify_ssl=not args.insecure,
        delay=args.delay,
        threads=args.threads,
        timeout=args.timeout,
        max_candidates=args.max_candidates,
        method_bypass=not args.no_method_bypass,
        param_pollution=not args.no_param_pollution,
        mass_assignment=not args.no_mass_assignment,
        soft_delete=not args.no_soft_delete,
        blind_idor=not args.no_blind_idor,
        extra_urls=combined_extra_urls,
        form_scan_targets=form_scan_targets,
        url_auth_overrides_a=url_auth_overrides_a,
        url_auth_overrides_b=url_auth_overrides_b,
        user_agent=getattr(args, "user_agent", "") or "random",
        on_log=live_log,
    )

    mode = f"dual-session ({args.label_a} vs {args.label_b})" if args.label_b else "single-session"

    if not args.json_output and not args.quiet:
        print(BOLD(f"[*] Target : {args.url}"))
        print(BOLD(f"[*] Method : {args.method.upper()}  Mode: {mode}"))
        print(BOLD(f"[*] Threads: {args.threads}  Candidates/param: {args.max_candidates}"))
        if args.insecure:
            print(YELLOW("[!] SSL verification disabled"))
        if args.delay > 0:
            print(DIM(f"[*] Delay between requests: {args.delay}s"))
        print()

    result = scan(args.url, opts)

    # Stored IDOR — multi-step chain scan
    chain_create = getattr(args, "chain_create", "")
    chain_read   = getattr(args, "chain_read", "")
    if chain_create and chain_read and args.label_b:
        from phaseaccess.engine.chainer import chain_scan as _chain_scan
        from phaseaccess.engine.scanner import _build_session_pair as _bsp
        chain_pair = _bsp(opts)
        # Parse "METHOD:URL" format
        if ":" in chain_create and chain_create.split(":")[0].upper() in (
            "GET", "POST", "PUT", "PATCH", "DELETE"
        ):
            chain_method, _, chain_url = chain_create.partition(":")
        else:
            chain_method, chain_url = "POST", chain_create
        chain_findings = _chain_scan(
            create_url=chain_url,
            create_method=chain_method.upper(),
            create_body=getattr(args, "chain_body", ""),
            read_url_template=chain_read,
            opts=opts,
            pair=chain_pair,
            log=live_log,
        )
        result.findings.extend(chain_findings)

    min_conf = getattr(args, "min_confidence", "").lower().strip()
    if min_conf and min_conf in CONFIDENCE_RANK:
        threshold = CONFIDENCE_RANK[min_conf]
        result.findings = [
            f for f in result.findings
            if CONFIDENCE_RANK.get(f.confidence.lower(), 99) <= threshold
        ]

    if args.json_output:
        output_text = json.dumps(result.to_dict(), indent=2)
        print(output_text)
        if args.output:
            _write_output(args.output, output_text)
        sys.exit(0 if result.total_findings == 0 else 1)

    lines = _format_human(result, mode)
    output_text = "\n".join(lines)
    print(output_text)

    if args.output:
        _write_output(args.output, output_text)

    sys.exit(0 if result.total_findings == 0 else 1)


def _write_output(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.write("\n")
        print(DIM(f"[*] Report saved to {path}"))
    except OSError as exc:
        print(YELLOW(f"[!] Could not write output to {path}: {exc}"), file=sys.stderr)


def _format_human(result: Any, mode: str) -> list[str]:
    lines = []
    lines.append(BOLD("=" * 65))
    lines.append(BOLD("  PhaseAccess — Scan Summary"))
    lines.append(BOLD("=" * 65))
    lines.append(f"  Target             : {result.target}")
    lines.append(f"  Mode               : {mode}")
    lines.append(f"  Duration           : {result.duration_s}s")
    lines.append(f"  Endpoints tested   : {result.endpoints_tested}")
    lines.append(f"  Parameters tested  : {result.parameters_tested}")
    lines.append(f"  Requests sent      : {result.requests_sent}")
    lines.append("")

    if result.total_findings == 0:
        lines.append(DIM("  No findings."))
    else:
        confirmed = result.confirmed_findings
        total = result.total_findings
        lines.append(GREEN(f"  Confirmed findings : {confirmed}"))
        lines.append(f"  Total findings     : {total}")
        lines.append("")

        for i, f in enumerate(result.findings, 1):
            conf_str = {
                Confidence.CONFIRMED: GREEN("[CONFIRMED]"),
                Confidence.HIGH:      GREEN("[HIGH]"),
                Confidence.MEDIUM:    YELLOW("[MEDIUM]"),
                Confidence.LOW:       DIM("[LOW]"),
                Confidence.INFO:      DIM("[INFO]"),
            }.get(f.confidence, f.confidence)

            lines.append(f"  {i:2}. {conf_str}  {f.idor_type}")
            lines.append(f"      URL       : {f.url}")
            lines.append(f"      Param     : {f.parameter} ({f.location})")
            lines.append(f"      ID type   : {f.id_type}")
            lines.append(f"      Original  : {f.original_value!r}")
            lines.append(f"      Tampered  : {f.tampered_value!r}")
            lines.append(f"      Status    : {f.baseline_status} → {f.tampered_status}")
            if f.owner_fields_leaked:
                lines.append(f"      Leaked    : {', '.join(f.owner_fields_leaked)}")
            if f.evidence_snippet:
                lines.append(f"      Evidence  : {DIM(f.evidence_snippet[:120])}")
            if f.notes:
                lines.append(f"      Signals   : {DIM(f.notes)}")
            if f.curl_command:
                lines.append(f"      Reproduce : {DIM(f.curl_command[:200])}")
            lines.append("")

    if result.harvested_ids:
        lines.append(DIM("  Harvested IDs (for chaining):"))
        for field_name, vals in list(result.harvested_ids.items())[:10]:
            lines.append(DIM(f"    {field_name}: {', '.join(vals[:5])}"))
        lines.append("")

    if result.errors:
        lines.append(RED("  Errors:"))
        for e in result.errors:
            lines.append(f"    - {e}")

    lines.append(BOLD("=" * 65))
    return lines


if __name__ == "__main__":
    main()
