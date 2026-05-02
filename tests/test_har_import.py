# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""Tests for phaseaccess.engine.har_import."""

from __future__ import annotations

import base64
import json
import os
import tempfile

import pytest

from phaseaccess.engine.har_import import (
    _parse_har_request,
    _parse_burp_item,
    _parse_raw_http_request,
    load_har,
    load_burp_xml,
    load_file,
    _ALL_HTTP_METHODS,
)
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# _parse_raw_http_request
# ---------------------------------------------------------------------------

class TestParseRawHttpRequest:
    def test_basic_get_strips_request_line(self):
        raw = "GET /users/42 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
        headers, body = _parse_raw_http_request(raw)
        assert headers.get("Host") == "example.com"
        assert headers.get("Accept") == "*/*"
        assert body == ""
        # Request line itself must not appear as a header key
        assert not any("GET" in k for k in headers)

    def test_post_with_body(self):
        raw = (
            "POST /api/login HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"user":"alice","pass":"s3cr3t"}'
        )
        headers, body = _parse_raw_http_request(raw)
        assert headers.get("Content-Type") == "application/json"
        assert body == '{"user":"alice","pass":"s3cr3t"}'

    def test_options_method_stripped(self):
        raw = "OPTIONS /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
        headers, body = _parse_raw_http_request(raw)
        assert "Host" in headers
        assert not any("OPTIONS" in k for k in headers)

    def test_head_method_stripped(self):
        raw = "HEAD /resource HTTP/1.1\r\nHost: example.com\r\n\r\n"
        headers, body = _parse_raw_http_request(raw)
        assert "Host" in headers
        assert not any("HEAD" in k for k in headers)

    def test_connect_method_stripped(self):
        raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        headers, body = _parse_raw_http_request(raw)
        assert "Host" in headers
        assert not any("CONNECT" in k for k in headers)

    def test_trace_method_stripped(self):
        raw = "TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        headers, body = _parse_raw_http_request(raw)
        assert "Host" in headers
        assert not any("TRACE" in k for k in headers)

    def test_delete_method_stripped(self):
        raw = "DELETE /items/5 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        headers, body = _parse_raw_http_request(raw)
        assert "Host" in headers
        assert not any("DELETE" in k for k in headers)

    def test_patch_method_stripped(self):
        raw = "PATCH /items/5 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{}"
        headers, body = _parse_raw_http_request(raw)
        assert "Content-Type" in headers
        assert not any("PATCH" in k for k in headers)

    def test_lf_only_line_endings(self):
        raw = "GET /path HTTP/1.1\nHost: test.com\n\n"
        headers, body = _parse_raw_http_request(raw)
        assert headers.get("Host") == "test.com"

    def test_no_body_separator(self):
        raw = "GET /path HTTP/1.1\r\nHost: test.com"
        headers, body = _parse_raw_http_request(raw)
        # Should not raise; headers parsed as best-effort
        assert isinstance(headers, dict)

    def test_empty_input(self):
        headers, body = _parse_raw_http_request("")
        assert headers == {}
        assert body == ""

    def test_all_http_methods_constant(self):
        """Every entry in _ALL_HTTP_METHODS must end with a space."""
        for m in _ALL_HTTP_METHODS:
            assert m.endswith(" "), f"{m!r} should end with a space"


# ---------------------------------------------------------------------------
# _parse_har_request
# ---------------------------------------------------------------------------

class TestParseHarRequest:
    def _make_har_req(self, **kwargs) -> dict:
        base = {
            "url": "https://api.example.com/users/1",
            "method": "GET",
            "headers": [],
            "queryString": [],
        }
        base.update(kwargs)
        return base

    def test_basic_get(self):
        target = _parse_har_request(self._make_har_req())
        assert target is not None
        assert target["url"] == "https://api.example.com/users/1"
        assert target["method"] == "GET"
        assert target["body"] == ""

    def test_headers_parsed(self):
        req = self._make_har_req(headers=[
            {"name": "Authorization", "value": "Bearer token123"},
            {"name": "Accept", "value": "application/json"},
        ])
        target = _parse_har_request(req)
        assert target["headers"]["Authorization"] == "Bearer token123"
        assert target["headers"]["Accept"] == "application/json"

    def test_http2_pseudo_headers_skipped(self):
        req = self._make_har_req(headers=[
            {"name": ":authority", "value": "example.com"},
            {"name": ":method", "value": "GET"},
            {"name": "Accept", "value": "*/*"},
        ])
        target = _parse_har_request(req)
        assert ":authority" not in target["headers"]
        assert "Accept" in target["headers"]

    def test_post_body_from_text(self):
        req = self._make_har_req(
            method="POST",
            postData={"mimeType": "application/json", "text": '{"id":1}'},
        )
        target = _parse_har_request(req)
        assert target["body"] == '{"id":1}'

    def test_post_body_from_params(self):
        req = self._make_har_req(
            method="POST",
            postData={
                "mimeType": "application/x-www-form-urlencoded",
                "text": "",
                "params": [
                    {"name": "user", "value": "alice"},
                    {"name": "id", "value": "42"},
                ],
            },
        )
        target = _parse_har_request(req)
        assert "user=alice" in target["body"]
        assert "id=42" in target["body"]

    def test_non_http_scheme_skipped(self):
        req = self._make_har_req(url="ftp://files.example.com/data")
        assert _parse_har_request(req) is None

    def test_missing_url_skipped(self):
        req = self._make_har_req(url="")
        assert _parse_har_request(req) is None

    def test_method_uppercased(self):
        req = self._make_har_req(method="get")
        target = _parse_har_request(req)
        assert target["method"] == "GET"


# ---------------------------------------------------------------------------
# load_har
# ---------------------------------------------------------------------------

class TestLoadHar:
    def _write_har(self, entries: list, tmp_path: str) -> str:
        har = {"log": {"version": "1.2", "entries": entries}}
        path = os.path.join(tmp_path, "test.har")
        with open(path, "w") as f:
            json.dump(har, f)
        return path

    def test_loads_simple_har(self, tmp_path):
        entries = [
            {
                "request": {
                    "url": "https://api.example.com/items/1",
                    "method": "GET",
                    "headers": [{"name": "Accept", "value": "application/json"}],
                }
            },
            {
                "request": {
                    "url": "https://api.example.com/items/2",
                    "method": "GET",
                    "headers": [],
                }
            },
        ]
        path = self._write_har(entries, str(tmp_path))
        targets = load_har(path)
        assert len(targets) == 2
        assert targets[0]["url"] == "https://api.example.com/items/1"
        assert targets[1]["url"] == "https://api.example.com/items/2"

    def test_skips_non_http_entries(self, tmp_path):
        entries = [
            {"request": {"url": "chrome://settings", "method": "GET", "headers": []}},
            {"request": {"url": "https://api.example.com/ok", "method": "GET", "headers": []}},
        ]
        path = self._write_har(entries, str(tmp_path))
        targets = load_har(path)
        assert len(targets) == 1

    def test_empty_har(self, tmp_path):
        path = self._write_har([], str(tmp_path))
        targets = load_har(path)
        assert targets == []

    def test_missing_file(self, tmp_path):
        targets = load_har(os.path.join(str(tmp_path), "nonexistent.har"))
        assert targets == []

    def test_invalid_json(self, tmp_path):
        path = os.path.join(str(tmp_path), "bad.har")
        with open(path, "w") as f:
            f.write("not json {{")
        targets = load_har(path)
        assert targets == []

    def test_top_level_entries_key(self, tmp_path):
        """Some exporters omit the 'log' wrapper."""
        har = {
            "entries": [
                {"request": {"url": "https://example.com/api", "method": "GET", "headers": []}}
            ]
        }
        path = os.path.join(str(tmp_path), "flat.har")
        with open(path, "w") as f:
            json.dump(har, f)
        targets = load_har(path)
        assert len(targets) == 1


# ---------------------------------------------------------------------------
# _parse_burp_item / load_burp_xml
# ---------------------------------------------------------------------------

def _make_burp_item_xml(url: str, method: str = "GET", raw_headers: str = "") -> ET.Element:
    item = ET.Element("item")
    url_el = ET.SubElement(item, "url")
    url_el.text = url
    method_el = ET.SubElement(item, "method")
    method_el.text = method
    if raw_headers:
        req_el = ET.SubElement(item, "request")
        req_el.set("base64", "false")
        req_el.text = raw_headers
    return item


class TestParseBurpItem:
    def test_basic_item(self):
        raw = "GET /api/users/1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
        item = _make_burp_item_xml("https://example.com/api/users/1", "GET", raw)
        target = _parse_burp_item(item)
        assert target is not None
        assert target["url"] == "https://example.com/api/users/1"
        assert target["method"] == "GET"
        assert target["headers"].get("Host") == "example.com"

    def test_base64_encoded_request(self):
        raw = "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
        encoded = base64.b64encode(raw.encode()).decode()
        item = ET.Element("item")
        ET.SubElement(item, "url").text = "https://example.com/login"
        ET.SubElement(item, "method").text = "POST"
        req_el = ET.SubElement(item, "request")
        req_el.set("base64", "true")
        req_el.text = encoded
        target = _parse_burp_item(item)
        assert target is not None
        assert target["headers"].get("Content-Type") == "application/json"
        assert target["body"] == '{"a":1}'

    def test_non_http_url_skipped(self):
        item = _make_burp_item_xml("ftp://evil.com/data", "GET")
        target = _parse_burp_item(item)
        assert target is None

    def test_missing_url_skipped(self):
        item = _make_burp_item_xml("", "GET")
        assert _parse_burp_item(item) is None

    def test_options_method_in_raw(self):
        raw = "OPTIONS /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
        item = _make_burp_item_xml("https://example.com/api", "OPTIONS", raw)
        target = _parse_burp_item(item)
        assert target is not None
        assert "Host" in target["headers"]
        assert not any("OPTIONS" in k for k in target["headers"])


class TestLoadBurpXml:
    def _write_burp(self, items_xml: str, tmp_path: str) -> str:
        content = f"<items burpVersion=\"2023\">{items_xml}</items>"
        path = os.path.join(tmp_path, "burp.xml")
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_loads_items(self, tmp_path):
        items_xml = (
            "<item><url>https://api.example.com/a</url><method>GET</method></item>"
            "<item><url>https://api.example.com/b</url><method>POST</method></item>"
        )
        path = self._write_burp(items_xml, str(tmp_path))
        targets = load_burp_xml(path)
        assert len(targets) == 2
        urls = {t["url"] for t in targets}
        assert "https://api.example.com/a" in urls
        assert "https://api.example.com/b" in urls

    def test_skips_invalid_items(self, tmp_path):
        items_xml = (
            "<item><url>ftp://invalid</url><method>GET</method></item>"
            "<item><url>https://api.example.com/ok</url><method>GET</method></item>"
        )
        path = self._write_burp(items_xml, str(tmp_path))
        targets = load_burp_xml(path)
        assert len(targets) == 1

    def test_missing_file(self, tmp_path):
        targets = load_burp_xml(os.path.join(str(tmp_path), "missing.xml"))
        assert targets == []

    def test_invalid_xml(self, tmp_path):
        path = os.path.join(str(tmp_path), "bad.xml")
        with open(path, "w") as f:
            f.write("<items><item><unclosed></items>")
        targets = load_burp_xml(path)
        assert targets == []


# ---------------------------------------------------------------------------
# load_file auto-detection
# ---------------------------------------------------------------------------

class TestLoadFile:
    def test_detects_har_by_content(self, tmp_path):
        har = {"log": {"entries": [
            {"request": {"url": "https://example.com/x", "method": "GET", "headers": []}}
        ]}}
        path = os.path.join(str(tmp_path), "traffic.har")
        with open(path, "w") as f:
            json.dump(har, f)
        targets = load_file(path)
        assert len(targets) == 1

    def test_detects_burp_by_extension(self, tmp_path):
        content = "<items><item><url>https://example.com/y</url><method>GET</method></item></items>"
        path = os.path.join(str(tmp_path), "export.xml")
        with open(path, "w") as f:
            f.write(content)
        targets = load_file(path)
        assert len(targets) == 1

    def test_detects_burp_by_first_char(self, tmp_path):
        """A file without .xml extension but starting with '<' should be treated as Burp XML."""
        content = "<items><item><url>https://example.com/z</url><method>GET</method></item></items>"
        path = os.path.join(str(tmp_path), "export.bin")
        with open(path, "w") as f:
            f.write(content)
        targets = load_file(path)
        assert len(targets) == 1

    def test_missing_file(self, tmp_path):
        targets = load_file(os.path.join(str(tmp_path), "no.file"))
        assert targets == []
