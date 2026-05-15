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

    if getattr(args, "crawl", False) and args.url:
        from commonhuman_core.http import HttpClient
        from commonhuman_core.crawler import crawl as _crawl
        crawl_headers = dict(session_a_headers)
        if args.cookie:
            crawl_headers.setdefault("Cookie", args.cookie)
        crawl_client = HttpClient(
            timeout=args.timeout,
            proxy=args.proxy,
            headers=crawl_headers,
            verify_ssl=not args.insecure,
        )
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Crawling {args.url} (depth={args.crawl_depth}, max={args.crawl_pages} pages) ..."))
        crawl_result = _crawl(
            start_url=args.url,
            injector=crawl_client,
            max_pages=args.crawl_pages,
            max_depth=args.crawl_depth,
            threads=args.threads,
        )
        seen = {args.url} | set(combined_extra_urls)
        discovered = [u for u in crawl_result.visited_urls if u not in seen and not _validate_extra_url(u)]
        combined_extra_urls.extend(discovered)
        if not args.quiet and not args.json_output:
            print(DIM(f"[*] Crawl complete — {len(discovered)} additional endpoint(s) queued"))

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
