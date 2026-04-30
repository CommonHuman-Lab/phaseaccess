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
    -t, --threads        Threads (default 5)
    --timeout            Request timeout seconds (default 15)
    --max-candidates     Tamper candidates per param (default 10)
    --no-method-bypass   Disable HTTP method bypass check
    --no-param-pollution Disable HTTP parameter pollution check
    --json               Output raw JSON
    -q, --quiet          Suppress live log output
"""

from __future__ import annotations

import argparse
import json
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
    if not url:
      print(YELLOW("  [!] URL is required."))
    elif not url.startswith(("http://", "https://")):
      print(YELLOW("  [!] URL must start with http:// or https://"))
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
  threads_str     = _prompt("  Threads",          default="5")
  timeout_str     = _prompt("  Timeout",          default="15", hint="seconds per request")
  max_cand_str    = _prompt("  Candidates/param", default="10")
  method_bypass   = _prompt_bool("  Test method bypass",     default=True)
  param_pollution = _prompt_bool("  Test param pollution",   default=True)

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
    threads=_safe_int(threads_str, 5, 1, 20),
    timeout=_safe_int(timeout_str, 15, 5, 120),
    max_candidates=_safe_int(max_cand_str, 10, 1, 50),
    no_method_bypass=not method_bypass,
    no_param_pollution=not param_pollution,
    json_output=False,
    quiet=False,
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
  p.add_argument("-t", "--threads",  type=int, default=5)
  p.add_argument("--timeout",        type=int, default=15)
  p.add_argument("--max-candidates", type=int, default=10)
  p.add_argument("--no-method-bypass",   action="store_true")
  p.add_argument("--no-param-pollution", action="store_true")
  p.add_argument("--json",           action="store_true", dest="json_output",
                 help="Output raw JSON")
  p.add_argument("-q", "--quiet",    action="store_true",
                 help="Suppress live log output")
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

  # No URL supplied → interactive mode
  if not args.url:
    args = interactive_prompts()
  elif not args.json_output:
    print(CYAN(BANNER))

  session_a_headers = _parse_headers(args.header)
  session_b_headers = _parse_headers(args.header_b)

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
    threads=args.threads,
    timeout=args.timeout,
    max_candidates=args.max_candidates,
    method_bypass=not args.no_method_bypass,
    param_pollution=not args.no_param_pollution,
    extra_urls=args.extra_url,
    on_log=live_log,
  )

  mode = f"dual-session ({args.label_a} vs {args.label_b})" if args.label_b else "single-session"

  if not args.json_output and not args.quiet:
    print(BOLD(f"[*] Target : {args.url}"))
    print(BOLD(f"[*] Method : {args.method.upper()}  Mode: {mode}"))
    print(BOLD(f"[*] Threads: {args.threads}  Candidates/param: {args.max_candidates}"))
    print()

  result = scan(args.url, opts)

  if args.json_output:
    print(json.dumps(result.to_dict(), indent=2))
    sys.exit(0 if result.total_findings == 0 else 1)

  # Human-readable summary
  print()
  print(BOLD("=" * 65))
  print(BOLD("  PhaseAccess — Scan Summary"))
  print(BOLD("=" * 65))
  print(f"  Target             : {result.target}")
  print(f"  Mode               : {mode}")
  print(f"  Duration           : {result.duration_s}s")
  print(f"  Endpoints tested   : {result.endpoints_tested}")
  print(f"  Parameters tested  : {result.parameters_tested}")
  print(f"  Requests sent      : {result.requests_sent}")
  print()

  if result.total_findings == 0:
    print(DIM("  No findings."))
  else:
    confirmed = result.confirmed_findings
    total     = result.total_findings
    print(GREEN(f"  Confirmed findings : {confirmed}"))
    print(f"  Total findings     : {total}")
    print()

    for i, f in enumerate(result.findings, 1):
      conf_str = {
        Confidence.CONFIRMED: GREEN("[CONFIRMED]"),
        Confidence.HIGH:      GREEN("[HIGH]"),
        Confidence.MEDIUM:    YELLOW("[MEDIUM]"),
        Confidence.LOW:       DIM("[LOW]"),
        Confidence.INFO:      DIM("[INFO]"),
      }.get(f.confidence, f.confidence)

      print(f"  {i:2}. {conf_str}  {f.idor_type}")
      print(f"      URL       : {f.url}")
      print(f"      Param     : {f.parameter} ({f.location})")
      print(f"      ID type   : {f.id_type}")
      print(f"      Original  : {f.original_value!r}")
      print(f"      Tampered  : {f.tampered_value!r}")
      print(f"      Status    : {f.baseline_status} → {f.tampered_status}")
      if f.owner_fields_leaked:
        print(f"      Leaked    : {', '.join(f.owner_fields_leaked)}")
      if f.evidence_snippet:
        print(f"      Evidence  : {DIM(f.evidence_snippet[:120])}")
      if f.notes:
        print(f"      Signals   : {DIM(f.notes)}")
      print()

  if result.harvested_ids:
    print(DIM("  Harvested IDs (for chaining):"))
    for field_name, vals in list(result.harvested_ids.items())[:10]:
      print(DIM(f"    {field_name}: {', '.join(vals[:5])}"))
    print()

  if result.errors:
    print(RED("  Errors:"))
    for e in result.errors:
      print(f"    - {e}")

  print(BOLD("=" * 65))
  sys.exit(0 if result.total_findings == 0 else 1)


if __name__ == "__main__":
  main()
