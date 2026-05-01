"""
PhaseAccess — __main__.py
Standalone CLI entry point.

Usage (from NyxStrike repo):
    python -m plugins.tools.phaseaccess -u https://api.target.com/users/42

Usage (from standalone PhaseAccess repo):
    python -m phaseaccess -u https://api.target.com/users/42

Run with no arguments for interactive mode.

Options:
    -u, --url            Target URL (required)
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
import os
import sys

try:
  from phaseaccess.engine import scan, ScanOptions
  from phaseaccess.engine.reporter import Confidence
except ImportError:
  _HERE = os.path.dirname(os.path.abspath(__file__))
  if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
  from engine import scan, ScanOptions
  from engine.reporter import Confidence

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
_USE_COLOUR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
  return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

RED    = lambda t: _c("31;1",    t)
GREEN  = lambda t: _c("38;5;46", t)
YELLOW = lambda t: _c("33;1",    t)
CYAN   = lambda t: _c("36",      t)
BOLD   = lambda t: _c("1",       t)
DIM    = lambda t: _c("2",       t)

BANNER = r"""
    ____  __                    ___                           
   / __ \/ /_  ____ _________  /   | _____________  __________
  / /_/ / __ \/ __ `/ ___/ _ \/ /| |/ ___/ ___/ _ \/ ___/ ___/
 / ____/ / / / /_/ (__  )  __/ ___ / /__/ /__/  __(__  |__  ) 
/_/   /_/ /_/\__,_/____/\___/_/  |_\___/\___/\___/____/____/  

  Authorization is just a suggestion.
  IDOR Detection Engine — CommonHuman-Lab
"""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_url(url: str) -> str:
  """Return an error message if URL is invalid, else empty string."""
  url = url.strip()
  if not url:
    return "URL is required."
  if not url.startswith(("http://", "https://")):
    return "URL must start with http:// or https://"
  return ""


# ---------------------------------------------------------------------------
# Interactive prompt helpers
# ---------------------------------------------------------------------------

def _prompt(label: str, default: str = "", hint: str = "") -> str:
  """Styled input prompt. Enter accepts default."""
  hint_str = f"  {DIM(hint)}" if hint else ""
  if default:
    display = f"{BOLD(label)} {DIM(f'[{default}]')}{hint_str}: "
  else:
    display = f"{BOLD(label)}{hint_str}: "
  try:
    val = input(display).strip()
  except (EOFError, KeyboardInterrupt):
    print()
    sys.exit(0)
  return val if val else default


def _prompt_bool(label: str, default: bool = False) -> bool:
  default_str = "Y/n" if default else "y/N"
  display = f"{BOLD(label)} {DIM(f'[{default_str}]')}: "
  try:
    val = input(display).strip().lower()
  except (EOFError, KeyboardInterrupt):
    print()
    sys.exit(0)
  if not val:
    return default
  return val in ("y", "yes", "1", "true")


def _section(title: str) -> None:
  print()
  print(DIM("  ─── " + title + " " + "─" * max(0, 40 - len(title))))


def _safe_int(val: str, default: int, lo: int, hi: int) -> int:
  try:
    return max(lo, min(int(val), hi))
  except (TypeError, ValueError):
    return default


def _safe_float(val: str, default: float, lo: float, hi: float) -> float:
  try:
    return max(lo, min(float(val), hi))
  except (TypeError, ValueError):
    return default


def interactive_prompts() -> argparse.Namespace:
  """Walk the user through all PhaseAccess scan options interactively."""
  print(CYAN(BANNER))
  print(DIM("  No arguments supplied — entering interactive mode."))
  print(DIM("  Press Enter to accept defaults. Ctrl+C to exit.\n"))

  # Target
  _section("Target")
  url = ""
  while not url:
    url = _prompt("  Target URL", hint="e.g. https://api.target.com/users/42")
    err = _validate_url(url)
    if err:
      print(YELLOW(f"  [!] {err}"))
      url = ""

  method = _prompt("  HTTP method", default="GET", hint="GET POST PUT PATCH DELETE")

  body = _prompt("  Request body", hint="form-encoded or JSON  (blank = none)")

  # Session A — owner
  _section("Session A — resource owner")
  label_a  = _prompt("  Label", default="session_a", hint='e.g. "admin", "owner"')
  cookie_a = _prompt("  Cookies", hint="name=val; name2=val2")
  token_a  = _prompt("  Bearer token", hint="eyJ...  (sets Authorization header)")
  headers_a: list[str] = []
  while True:
    h = _prompt("  Header", hint="KEY:VALUE  (blank to finish)")
    if not h:
      break
    headers_a.append(h)
  if token_a:
    headers_a.append(f"Authorization: Bearer {token_a}")

  # Session B — attacker (optional)
  _section("Session B — attacker  (optional, enables dual-session mode)")
  label_b  = _prompt("  Label", hint='e.g. "user", "attacker"  (blank = single-session)')
  cookie_b = ""
  token_b  = ""
  headers_b: list[str] = []
  if label_b:
    cookie_b = _prompt("  Cookies", hint="name=val; name2=val2")
    token_b  = _prompt("  Bearer token", hint="eyJ...")
    while True:
      h = _prompt("  Header", hint="KEY:VALUE  (blank to finish)")
      if not h:
        break
      headers_b.append(h)
    if token_b:
      headers_b.append(f"Authorization: Bearer {token_b}")

  # Extra endpoints
  _section("Extra endpoints  (optional)")
  extra_urls: list[str] = []
  while True:
    u = _prompt("  Additional URL", hint="blank to finish")
    if not u:
      break
    extra_urls.append(u)

  # Advanced
  _section("Advanced options")
  proxy           = _prompt("  Proxy",            hint="http://127.0.0.1:8080")
  insecure        = _prompt_bool("  Skip SSL verification (--insecure)", default=False)
  delay_str       = _prompt("  Delay between requests (s)", default="0",
                             hint="e.g. 0.5 for rate limiting")
  threads_str     = _prompt("  Threads",          default="5")
  timeout_str     = _prompt("  Timeout",          default="15", hint="seconds per request")
  max_cand_str    = _prompt("  Candidates/param", default="10")
  method_bypass   = _prompt_bool("  Test method bypass",     default=True)
  param_pollution = _prompt_bool("  Test param pollution",   default=True)
  output          = _prompt("  Save report to file", hint="blank = stdout only")

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
    threads=_safe_int(threads_str, 5, 1, 20),
    timeout=_safe_int(timeout_str, 15, 5, 120),
    max_candidates=_safe_int(max_cand_str, 10, 1, 50),
    no_method_bypass=not method_bypass,
    no_param_pollution=not param_pollution,
    no_mass_assignment=False,
    no_soft_delete=False,
    no_blind_idor=False,
    json_output=False,
    quiet=False,
    verbose=False,
    output=output,
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
  p.add_argument("-u", "--url",      default="",    help="Target URL")
  p.add_argument("-X", "--method",   default="GET", help="HTTP method (default GET)")
  p.add_argument("-d", "--data",     default="",    help="Request body")
  p.add_argument("-H", "--header",   action="append", default=[], metavar="KEY:VALUE",
                 help="Session A header (repeatable)")
  p.add_argument("-c", "--cookie",   default="",    help="Session A cookie string")
  p.add_argument("--label-a",        default="session_a", help="Label for session A")
  p.add_argument("--header-b",       action="append", default=[], metavar="KEY:VALUE",
                 help="Session B header (repeatable)")
  p.add_argument("--cookie-b",       default="",    help="Session B cookie string")
  p.add_argument("--label-b",        default="",
                 help="Session B label — enables dual-session mode")
  p.add_argument("--extra-url",      action="append", default=[], metavar="URL",
                 help="Extra endpoint URL (repeatable)")
  p.add_argument("--proxy",          default="",    help="HTTP proxy URL")
  p.add_argument("--insecure",       action="store_true",
                 help="Disable SSL certificate verification")
  p.add_argument("--delay",          type=float, default=0.0,
                 help="Seconds between requests (default 0)")
  p.add_argument("-t", "--threads",  type=int, default=5)
  p.add_argument("--timeout",        type=int, default=15)
  p.add_argument("--max-candidates", type=int, default=10)
  p.add_argument("--targets",        default="",
                 help="Import targets from HAR / Burp XML / JSON file")
  p.add_argument("--min-confidence", default="", dest="min_confidence",
                 help="Minimum confidence to report: confirmed high medium low info")
  p.add_argument("--user-agent",     default="", dest="user_agent",
                 help="Override User-Agent header (default: PhaseAccess/1.0)")
  p.add_argument("--no-method-bypass",   action="store_true")
  p.add_argument("--no-param-pollution", action="store_true")
  p.add_argument("--no-mass-assignment", action="store_true")
  p.add_argument("--no-soft-delete",     action="store_true")
  p.add_argument("--no-blind-idor",      action="store_true")
  p.add_argument("--json",           action="store_true", dest="json_output",
                 help="Output raw JSON")
  p.add_argument("-o", "--output",   default="",
                 help="Save report to file (human text, or JSON with --json)")
  p.add_argument("-q", "--quiet",    action="store_true",
                 help="Suppress live log output")
  p.add_argument("-v", "--verbose",  action="store_true",
                 help="Enable debug logging")
  return p


def _parse_headers(raw_list: list) -> dict:
  h = {}
  for item in raw_list:
    if ':' in item:
      k, _, v = item.partition(':')
      h[k.strip()] = v.strip()
  return h


def main() -> None:
  parser = build_parser()
  args   = parser.parse_args()

  # Configure logging
  log_level = logging.DEBUG if args.verbose else logging.WARNING
  logging.basicConfig(
    level=log_level,
    format="%(name)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
  )

  # Validate URL in CLI mode
  if args.url:
    err = _validate_url(args.url)
    if err:
      print(YELLOW(f"[!] {err}"), file=sys.stderr)
      sys.exit(2)

  # No URL supplied → interactive mode
  if not args.url:
    args = interactive_prompts()
  elif not args.json_output:
    print(CYAN(BANNER))

  session_a_headers = _parse_headers(args.header)
  session_b_headers = _parse_headers(args.header_b)

  # --targets: load extra URLs from HAR / Burp XML / JSON file
  imported_extra_urls: list[str] = []
  if getattr(args, 'targets', ''):
    try:
      from phaseaccess.engine.har_import import load_file as _load_import
    except ImportError:
      from engine.har_import import load_file as _load_import  # type: ignore
    imported_targets = _load_import(args.targets)
    for t in imported_targets:
      u = t.get('url', '')
      if u and u not in imported_extra_urls:
        imported_extra_urls.append(u)
    if not args.quiet and not args.json_output:
      print(DIM(f"[*] Imported {len(imported_extra_urls)} URL(s) from {args.targets}"))

  combined_extra_urls = list(args.extra_url) + imported_extra_urls

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
    user_agent=getattr(args, 'user_agent', '') or 'PhaseAccess/1.0',
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

  # Apply --min-confidence filter
  min_conf = getattr(args, 'min_confidence', '').lower().strip()
  _CONF_RANK = {'confirmed': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
  if min_conf and min_conf in _CONF_RANK:
    threshold = _CONF_RANK[min_conf]
    result.findings = [
      f for f in result.findings
      if _CONF_RANK.get(f.confidence.lower(), 99) <= threshold
    ]

  if args.json_output:
    output_text = json.dumps(result.to_dict(), indent=2)
    print(output_text)
    if args.output:
      _write_output(args.output, output_text)
    sys.exit(0 if result.total_findings == 0 else 1)

  # Human-readable summary
  lines = _format_human(result, mode)
  output_text = "\n".join(lines)
  print(output_text)

  if args.output:
    _write_output(args.output, output_text)

  sys.exit(0 if result.total_findings == 0 else 1)


def _write_output(path: str, text: str) -> None:
  try:
    with open(path, 'w', encoding='utf-8') as fh:
      fh.write(text)
      fh.write('\n')
    print(DIM(f"[*] Report saved to {path}"))
  except OSError as exc:
    print(YELLOW(f"[!] Could not write output to {path}: {exc}"), file=sys.stderr)


def _format_human(result: any, mode: str) -> list[str]:
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
    total     = result.total_findings
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
