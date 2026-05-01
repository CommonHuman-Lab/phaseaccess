"""
T6-22: Scanner integration test using a real in-process HTTP server.

Spins up a minimal HTTP server on localhost, runs a full scan against it,
and asserts that PhaseAccess finds the planted IDOR.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from phaseaccess.engine.scanner import scan, ScanOptions
from phaseaccess.engine.reporter import Confidence


# ---------------------------------------------------------------------------
# Tiny mock API server
# ---------------------------------------------------------------------------

_USERS = {
  "1": {"user_id": "1", "email": "alice@example.com", "secret": "alice-secret"},
  "2": {"user_id": "2", "email": "bob@example.com",   "secret": "bob-secret"},
}


class _MockHandler(BaseHTTPRequestHandler):
  """
  GET /users/<id>
    - Returns user JSON (200) for ids 1 and 2
    - Returns 404 for unknown ids

  No actual auth enforcement — any request for user 1 or 2 returns data.
  This simulates a flat IDOR vulnerability.
  """

  def log_message(self, *args):
    pass  # silence server logs during tests

  def do_GET(self):
    path = urlparse(self.path).path
    parts = [p for p in path.split('/') if p]

    if len(parts) == 2 and parts[0] == 'users':
      uid = parts[1]
      if uid in _USERS:
        body = json.dumps(_USERS[uid]).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return

    self.send_response(404)
    self.send_header('Content-Type', 'application/json')
    self.end_headers()
    self.wfile.write(b'{"error": "not found"}')


def _start_server():
  server = HTTPServer(('127.0.0.1', 0), _MockHandler)
  t = threading.Thread(target=server.serve_forever, daemon=True)
  t.start()
  return server


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestScannerIntegration:

  @pytest.fixture(scope="class")
  def server(self):
    srv = _start_server()
    yield srv
    srv.shutdown()

  def _base_url(self, server, uid="1"):
    port = server.server_address[1]
    return f"http://127.0.0.1:{port}/users/{uid}"

  def test_finds_idor_single_session(self, server):
    """
    Single-session mode: scan user 1's resource.
    Candidates include integer +1, +2 etc. which will hit user 2's data.
    The comparator should detect that user_id and email changed.
    """
    url = self._base_url(server, "1")
    opts = ScanOptions(
      method="GET",
      max_candidates=5,
      method_bypass=False,
      param_pollution=False,
      mass_assignment=False,
      soft_delete=False,
      blind_idor=False,
      threads=1,
      timeout=5,
    )
    result = scan(url, opts)
    assert result.endpoints_tested >= 1
    assert result.parameters_tested >= 1
    # Should detect that user_id changed in the response (IDOR)
    assert result.total_findings >= 1
    confidences = {f.confidence for f in result.findings}
    # At minimum MEDIUM; cross-user ownership change should trigger HIGH/CONFIRMED
    assert any(c in confidences for c in (
      Confidence.CONFIRMED, Confidence.HIGH, Confidence.MEDIUM
    ))

  def test_findings_have_curl_command(self, server):
    """All findings should include a non-empty curl_command."""
    url = self._base_url(server, "1")
    opts = ScanOptions(
      method="GET",
      max_candidates=3,
      method_bypass=False,
      param_pollution=False,
      mass_assignment=False,
      soft_delete=False,
      blind_idor=False,
      threads=1,
      timeout=5,
    )
    result = scan(url, opts)
    for f in result.findings:
      assert f.curl_command, f"Finding {f.parameter} missing curl_command"
      assert "curl" in f.curl_command

  def test_no_duplicate_findings(self, server):
    """Deduplication: each (url, parameter, idor_type) appears at most once."""
    url = self._base_url(server, "1")
    opts = ScanOptions(
      method="GET",
      max_candidates=8,
      method_bypass=False,
      param_pollution=False,
      mass_assignment=False,
      soft_delete=False,
      blind_idor=False,
      threads=1,
      timeout=5,
    )
    result = scan(url, opts)
    keys = [(f.url, f.parameter, f.idor_type) for f in result.findings]
    assert len(keys) == len(set(keys)), "Duplicate findings found"

  def test_dual_session_confirmed(self, server):
    """
    Dual-session mode: session_a owns user 1, session_b is user 2.
    Scan user 1's resource as session_b — should get CONFIRMED.
    """
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/users/1"

    opts = ScanOptions(
      session_a_label="alice",
      session_b_label="bob",
      method="GET",
      max_candidates=3,
      method_bypass=False,
      param_pollution=False,
      mass_assignment=False,
      soft_delete=False,
      blind_idor=False,
      threads=1,
      timeout=5,
    )
    result = scan(url, opts)
    assert result.total_findings >= 1
