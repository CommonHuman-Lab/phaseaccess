# PhaseAccess

Native IDOR and broken object-level authorization (BOLA) detection engine.

## Install

```bash
pip install phaseaccess
```

## Usage

```bash
# Single-session mode
phaseaccess -u "https://api.target.com/users/42" \
  -H "Authorization: Bearer <token>"

# Dual-session mode (owner vs attacker)
phaseaccess -u "https://api.target.com/users/42" \
  -H "Authorization: Bearer <owner_token>" --label-a owner \
  --header-b "Authorization: Bearer <attacker_token>" --label-b attacker
```

## Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL |
| `-X, --method` | HTTP method (default GET) |
| `-d, --data` | Request body |
| `-H KEY:VALUE` | Session A header (repeatable) |
| `-c, --cookie` | Session A cookie string |
| `--label-a` | Label for session A |
| `--header-b KEY:VALUE` | Session B header (repeatable) |
| `--cookie-b` | Session B cookie string |
| `--label-b` | Label for session B (enables dual-session mode) |
| `--max-candidates` | Tamper candidates per param (default 10) |
| `--json` | Raw JSON output |

---

## 📜 License

Licensed under the AGPL3.
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.