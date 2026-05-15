# PhaseAccess

The most thorough open-source IDOR / BOLA scanner available.  
PhaseAccess goes beyond simple ID enumeration — it understands *ownership*, *sessions*, and *evidence*.

```bash
pip install phaseaccess

# Install in virtual env
python3 -m venv .venv
source .venv/bin/activate
pip install phaseaccess
```

> Point it at a target. Get findings. Drop it in a pipeline.

---

## Why use PhaseAccess?

- **Semantic diffing** — compares ownership fields (`user_id`, `email`, `owner_id`) across responses, not just status codes
- **Dual-session mode** — use two sets of credentials; get CONFIRMED findings when user B's data appears in user A's request
- **Variance-aware baseline** — two baseline fetches detect per-request noise (nonces, timestamps, session tokens) so they don't pollute the diff
- **JWT tampering** — extracts and fuzzes JWT claims from Authorization headers
- **Cookie extraction** — scans individual cookie values for ID-like patterns
- **Timing oracle** — flags significant latency deltas as a supporting signal
- **HAR / Burp Suite import** — replay your proxy traffic directly
- **curl reproduction** — every finding ships a ready-to-paste curl command

---

## Quick start

```bash
# Single-session: enumerate IDs around /users/42
phaseaccess -u "https://api.example.com/users/42" \
  -H "Authorization: Bearer <your_token>"

# Dual-session: owner vs attacker — gets you CONFIRMED findings
phaseaccess -u "https://api.example.com/users/42" \
  -H "Authorization: Bearer <owner_token>" --label-a owner \
  --header-b "Authorization: Bearer <attacker_token>" --label-b attacker

# Crawl the whole app and test every discovered endpoint
phaseaccess -u "https://api.example.com/" \
  -H "Authorization: Bearer <token>" --crawl --crawl-pages 100 --crawl-depth 4

# JS-rendered SPA — use headless Chromium for endpoint discovery
phaseaccess -u "https://api.example.com/" \
  -H "Authorization: Bearer <token>" --browser-crawl

# Form login — authenticate both sessions before scanning
phaseaccess -u "https://app.example.com/profile" \
  --login-url "https://app.example.com/login" \
  --login-user alice --login-pass alice_pw \
  --login-url-b "https://app.example.com/login" \
  --login-user-b bob --login-pass-b bob_pw

# Import all endpoints from an OpenAPI / Swagger spec
phaseaccess -u "https://api.example.com/" \
  -H "Authorization: Bearer <token>" \
  --openapi https://api.example.com/openapi.json

# Stored IDOR chainer: alice creates a resource, check if bob can read it
phaseaccess -u "https://api.example.com/documents/1" \
  -H "Authorization: Bearer <alice_token>" --label-a alice \
  --header-b "Authorization: Bearer <bob_token>" --label-b bob \
  --chain-create "POST:https://api.example.com/documents" \
  --chain-body '{"title":"test"}' \
  --chain-read "https://api.example.com/documents/{id}"

# POST endpoint
phaseaccess -u "https://api.example.com/orders" \
  -X POST -d '{"order_id": 1001}' \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"

# Import your Burp Suite export and scan everything at once
phaseaccess -u "https://api.example.com/users/1" \
  -H "Authorization: Bearer <token>" \
  --targets burp_export.xml

# Save a JSON report, suppress noise, gate on medium+
phaseaccess -u "https://api.example.com/users/42" \
  -H "Authorization: Bearer <token>" \
  --min-confidence medium --json -o report.json
```

---

## What it detects

| Type | Description |
|------|-------------|
| **Horizontal IDOR** | User A reads/modifies user B's objects |
| **Vertical IDOR** | Low-priv user accesses admin/elevated objects |
| **Method bypass** | Endpoint blocks GET but not PUT/DELETE/PATCH |
| **Param pollution** | `?id=own&id=victim` — server picks the wrong one |
| **Mass assignment** | Injected `user_id`/`owner_id` fields accepted by server |
| **Soft-delete bypass** | `?include_deleted=true` reveals logically deleted resources |
| **Blind IDOR** | Status code flips 403→200 with no body — side-effect may have occurred |
| **JWT claim tampering** | `sub`, `user_id`, `role` mutations with `alg:none` test |
| **JWT kid injection** | `kid` header path traversal (`../../dev/null`, `../../../../etc/passwd`) |
| **JWT algorithm confusion** | RS256 → HS256 downgrade with empty signature |
| **JWT exp removal** | Strip expiry claim to test for missing validation |
| **Hex ID enumeration** | Detects and mutates short hex identifiers (e.g. `fa1`, `1a2b3c`) |
| **Direct cross-session check** | Session B fetches session A's URL; confirms horizontal IDOR when ownership values leak |
| **Stored IDOR chaining** | Session A creates resource, session B reads via `--chain-read` template |

---

## All options

```
Usage: phaseaccess [options]

Target:
  -u, --url            Target URL (required, or use interactive mode)
  -X, --method         HTTP method (default: GET)
  -d, --data           Request body (form-encoded or JSON)
  --extra-url URL      Additional endpoint to test (repeatable)
  --targets FILE       Import targets from HAR / Burp Suite XML / JSON file
  --crawl              BFS-crawl the target and test all discovered endpoints
  --crawl-pages N      Max pages to crawl (default: 100)
  --crawl-depth N      Max crawl depth (default: 3)
  --browser-crawl      Headless Chromium endpoint discovery for JS-rendered apps
  --openapi FILE/URL   OpenAPI/Swagger spec — imports all endpoints to scan
  --base-url URL       Base URL override when loading an OpenAPI spec

Session A — resource owner:
  -H KEY:VALUE         Request header (repeatable)
  -c, --cookie         Cookie string
  --label-a LABEL      Session label (default: session_a)
  --login-url URL      Login form URL for session A — authenticates before scanning
  --login-user USER    Username for session A form login
  --login-pass PASS    Password for session A form login

Session B — attacker (enables dual-session mode):
  --header-b KEY:VALUE Header (repeatable)
  --cookie-b           Cookie string
  --label-b LABEL      Session label (default: session_b)
  --login-url-b URL    Login form URL for session B
  --login-user-b USER  Username for session B form login
  --login-pass-b PASS  Password for session B form login

Network:
  --proxy URL          HTTP proxy (e.g. http://127.0.0.1:8080)
  --insecure           Disable SSL certificate verification
  --delay SECS         Delay between requests (rate limiting)
  --timeout SECS       Request timeout (default: 15)
  --user-agent STRING  Override User-Agent (default: PhaseAccess/1.0)

Scan control:
  -t, --threads N      Parallel threads (default: 5)
  --max-candidates N   Tamper candidates per parameter (default: 10)
  --no-method-bypass   Disable HTTP method bypass check
  --no-param-pollution Disable HTTP parameter pollution check
  --no-mass-assignment Disable mass assignment check
  --no-soft-delete     Disable soft-delete bypass check
  --no-blind-idor      Disable blind IDOR check
  --chain-create METHOD:URL  Stored IDOR: URL where session A creates a resource
  --chain-body BODY    Request body for the chain-create POST
  --chain-read URL     URL template where session B reads (use {id} placeholder)

Output:
  --min-confidence     Minimum confidence to report: confirmed high medium low info
  --json               Raw JSON output
  -o, --output FILE    Save report to file
  -q, --quiet          Suppress live log output
  -v, --verbose        Debug logging
```

---

## Confidence levels

| Level | Meaning |
|-------|---------|
| **CONFIRMED** | Dual-session: foreign user's ownership value appeared in response |
| **HIGH** | Ownership field changed value, or 200 returned where 403 was baseline |
| **MEDIUM** | JSON structure changed or substantial body diff |
| **LOW** | Status code change or timing oracle signal only |
| **INFO** | ID enumeration possible; no access confirmed |

---

## Dual-session mode (recommended)

Dual-session mode is the most powerful way to use PhaseAccess.  
You supply two credential sets:

- **Session A** — the resource owner (the user who *should* have access)
- **Session B** — the attacker (a different user who *should not* have access)

PhaseAccess uses session A's response to harvest ownership values (`user_id`, `email`, etc.), then replays tampered requests as session B. If session B's response contains session A's ownership values — or vice versa — the finding is **CONFIRMED**.

```bash
phaseaccess \
  -u "https://api.example.com/documents/d9a3f7c2" \
  -H "Authorization: Bearer alice_token" --label-a alice \
  --header-b "Authorization: Bearer bob_token" --label-b bob
```

---

## HAR / Burp Suite import

Feed your proxy traffic directly into PhaseAccess:

```bash
# Burp Suite: Proxy → HTTP history → select requests → Save items → XML
phaseaccess -u "https://api.example.com/users/1" \
  -H "Authorization: Bearer <token>" \
  --targets burp_history.xml

# HAR export (Chrome DevTools → Network → Export HAR)
phaseaccess -u "https://api.example.com/users/1" \
  -H "Authorization: Bearer <token>" \
  --targets devtools.har
```

All imported URLs are tested alongside the primary target.

---

## Python API

```python
from phaseaccess.engine.scanner import scan, ScanOptions

result = scan(
    "https://api.example.com/users/42",
    ScanOptions(
        session_a_headers={"Authorization": "Bearer alice_token"},
        session_a_label="alice",
        session_b_headers={"Authorization": "Bearer bob_token"},
        session_b_label="bob",
        max_candidates=15,
        threads=3,
    ),
)

for finding in result.findings:
    print(f"[{finding.confidence}] {finding.idor_type} — {finding.parameter}")
    print(f"  {finding.curl_command}")
```

---

## Sample output

```
  1. [CONFIRMED]  horizontal_idor
      URL       : https://api.example.com/users/42
      Param     : path[1] (path_segment)
      ID type   : integer
      Original  : '42'
      Tampered  : '43'
      Status    : 200 → 200
      Leaked    : user_id, email
      Evidence  : user_id: baseline='42', tampered='43'
      Reproduce : curl -s -X GET -H 'Authorization: Bearer ...' https://api.example.com/users/43
```

---

## How it works

```
Target URL(s)
    │
    ├─ 0. Auth & discovery (optional)
    │      Form login (session A + B), OpenAPI import,
    │      BFS crawl or headless browser crawl
    │
    ├─ 1. Baseline (×2 fetches → variance-aware stable fingerprint)
    │      Direct cross-session check: does session B see session A's
    │      ownership values on session A's URL? → CONFIRMED immediately
    │
    ├─ 2. Extract object refs
    │      URL params, path segments, JSON body, form body,
    │      headers (X-User-Id etc.), cookies, Authorization JWT
    │
    ├─ 3. Generate tamper candidates per ref
    │      integer neighbours, UUID v1 timestamp deltas,
    │      nil/max UUID, Base64 mutations, hex neighbours,
    │      JWT claim tampering (sub/user_id/role + alg:none),
    │      JWT kid path traversal, RS256→HS256 confusion, exp removal,
    │      foreign IDs from session B's harvest
    │
    ├─ 4. Fire tampered requests (session B if dual, else session A)
    │      Compare fingerprints:
    │        ownership field values, JSON structure, body hash,
    │        status code delta, timing oracle
    │      Dual-session + leaked ownership fields → upgrade to CONFIRMED
    │
    ├─ 5. Additional checks
    │      Method bypass, param pollution, mass assignment
    │        (mass assignment follow-up GET confirms ownership change),
    │      soft-delete bypass, blind IDOR
    │
    ├─ 6. Stored IDOR chaining (--chain-create / --chain-read)
    │      Session A creates resource → harvest IDs from response
    │      Session B reads via URL template → CONFIRMED if ownership leaks
    │
    └─ 7. Deduplicate + report
           Highest-confidence per (url, param, type)
           curl reproduction command on every finding
```

---

## 📜 License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
