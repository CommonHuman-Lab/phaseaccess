# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""Tests for phaseaccess.engine.extractor"""
import pytest

from phaseaccess.engine.extractor import (
    extract_from_url,
    extract_from_body,
    extract_from_headers,
    harvest_ids_from_response,
    extract_all,
    _is_id_param,
    _looks_like_id,
    _flatten_json,
)
from phaseaccess.engine.reporter import IDORLocation, IDType


# ---------------------------------------------------------------------------
# extract_from_url
# ---------------------------------------------------------------------------

class TestExtractFromUrl:
    def test_integer_query_param(self):
        refs = extract_from_url("https://api.example.com/users?id=42")
        assert any(r.param == "id" and r.value == "42" for r in refs)

    def test_uuid_query_param(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        refs = extract_from_url(f"https://api.example.com/users?user_id={uuid}")
        assert any(r.param == "user_id" for r in refs)

    def test_integer_path_segment(self):
        refs = extract_from_url("https://api.example.com/users/42/profile")
        path_refs = [r for r in refs if r.location == IDORLocation.PATH_SEGMENT]
        assert any(r.value == "42" for r in path_refs)

    def test_uuid_path_segment(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        refs = extract_from_url(f"https://api.example.com/items/{uuid}")
        path_refs = [r for r in refs if r.location == IDORLocation.PATH_SEGMENT]
        assert any(r.value == uuid for r in path_refs)

    def test_no_ids_returns_empty(self):
        refs = extract_from_url("https://api.example.com/health")
        assert refs == []

    def test_id_suffix_param_name_detected(self):
        # "order_id" ends in _id
        refs = extract_from_url("https://api.example.com/orders?order_id=99")
        assert any(r.param == "order_id" for r in refs)

    def test_method_stored(self):
        refs = extract_from_url("https://api.example.com/users?id=1", method="POST")
        assert all(r.method == "POST" for r in refs)

    def test_path_segment_index_stored(self):
        refs = extract_from_url("https://api.example.com/users/42/orders/7")
        path_refs = [r for r in refs if r.location == IDORLocation.PATH_SEGMENT]
        params = {r.param for r in path_refs}
        assert "path[1]" in params or "path[3]" in params  # depends on index


# ---------------------------------------------------------------------------
# extract_from_body
# ---------------------------------------------------------------------------

class TestExtractFromBody:
    def test_json_body_integer_id(self):
        refs = extract_from_body(
            "https://api.example.com/orders", "POST",
            '{"order_id": 42, "item": "widget"}',
        )
        assert any(r.param == "order_id" for r in refs)

    def test_json_body_uuid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        refs = extract_from_body(
            "https://api.example.com/items", "POST",
            f'{{"item_id": "{uuid}"}}',
        )
        assert any(r.param == "item_id" for r in refs)

    def test_form_encoded_body(self):
        refs = extract_from_body(
            "https://api.example.com/users", "POST",
            "user_id=42&action=delete",
        )
        assert any(r.param == "user_id" for r in refs)

    def test_empty_body_returns_empty(self):
        refs = extract_from_body("https://api.example.com/", "POST", "")
        assert refs == []

    def test_invalid_json_not_crash(self):
        refs = extract_from_body(
            "https://api.example.com/", "POST", "{not valid json"
        )
        # Should not raise, may return empty
        assert isinstance(refs, list)

    def test_json_body_context_stored(self):
        body = '{"user_id": 5, "name": "Alice"}'
        refs = extract_from_body("https://api.example.com/", "PUT", body)
        json_refs = [r for r in refs if r.location == IDORLocation.JSON_BODY]
        assert any(r.body_context is not None for r in json_refs)


# ---------------------------------------------------------------------------
# extract_from_headers
# ---------------------------------------------------------------------------

class TestExtractFromHeaders:
    def test_x_user_id_header(self):
        refs = extract_from_headers(
            "https://api.example.com/", "GET",
            {"X-User-Id": "42"},
        )
        assert any(r.value == "42" for r in refs)

    def test_unknown_header_ignored(self):
        refs = extract_from_headers(
            "https://api.example.com/", "GET",
            {"Accept": "application/json"},
        )
        assert refs == []

    def test_x_tenant_id_detected(self):
        refs = extract_from_headers(
            "https://api.example.com/", "GET",
            {"X-Tenant-Id": "org-99"},
        )
        assert any(r.location == IDORLocation.HEADER for r in refs)


# ---------------------------------------------------------------------------
# harvest_ids_from_response
# ---------------------------------------------------------------------------

class TestHarvestIdsFromResponse:
    def test_user_id_extracted(self):
        body = '{"id": 1, "user_id": 42, "name": "Alice"}'
        harvested = harvest_ids_from_response("https://api.example.com/", body)
        assert any(h.field == "user_id" for h in harvested)

    def test_email_extracted(self):
        body = '{"id": 1, "email": "alice@example.com"}'
        harvested = harvest_ids_from_response("https://api.example.com/", body)
        assert any(h.field == "email" for h in harvested)

    def test_null_values_skipped(self):
        body = '{"user_id": null}'
        harvested = harvest_ids_from_response("https://api.example.com/", body)
        assert not any(h.field == "user_id" for h in harvested)

    def test_non_json_body_returns_empty(self):
        body = "plain text response"
        harvested = harvest_ids_from_response("https://api.example.com/", body)
        assert harvested == []

    def test_nested_field_extracted(self):
        body = '{"data": {"user_id": 55}}'
        harvested = harvest_ids_from_response("https://api.example.com/", body)
        assert any(h.field.endswith("user_id") for h in harvested)

    def test_malformed_json_no_crash(self):
        body = '{"broken": '
        harvested = harvest_ids_from_response("https://api.example.com/", body)
        assert isinstance(harvested, list)


# ---------------------------------------------------------------------------
# extract_all
# ---------------------------------------------------------------------------

class TestExtractAll:
    def test_combines_url_and_body(self):
        refs = extract_all(
            "https://api.example.com/users/42",
            "POST",
            body='{"order_id": 7}',
        )
        locations = {r.location for r in refs}
        assert IDORLocation.PATH_SEGMENT in locations
        assert IDORLocation.JSON_BODY in locations

    def test_combines_headers(self):
        refs = extract_all(
            "https://api.example.com/users/42",
            "GET",
            headers={"X-User-Id": "99"},
        )
        locations = {r.location for r in refs}
        assert IDORLocation.HEADER in locations


# ---------------------------------------------------------------------------
# _is_id_param
# ---------------------------------------------------------------------------

class TestIsIdParam:
    def test_exact_keyword_id(self):
        assert _is_id_param("id") is True

    def test_exact_keyword_user_id(self):
        assert _is_id_param("user_id") is True

    def test_suffix_match(self):
        assert _is_id_param("invoice_id") is True

    def test_non_id_param(self):
        assert _is_id_param("name") is False

    def test_case_insensitive(self):
        assert _is_id_param("UserId") is True


# ---------------------------------------------------------------------------
# _looks_like_id
# ---------------------------------------------------------------------------

class TestLooksLikeId:
    def test_integer_looks_like_id(self):
        assert _looks_like_id("42") is True

    def test_uuid_looks_like_id(self):
        assert _looks_like_id("550e8400-e29b-41d4-a716-446655440000") is True

    def test_plain_word_not_id(self):
        assert _looks_like_id("hello") is False

    def test_empty_string_not_id(self):
        assert _looks_like_id("") is False

    def test_too_long_string_not_id(self):
        assert _looks_like_id("a" * 600) is False


# ---------------------------------------------------------------------------
# _flatten_json
# ---------------------------------------------------------------------------

class TestFlattenJson:
    def test_flat_dict(self):
        result = dict(_flatten_json({"a": 1, "b": "x"}))
        assert result["a"] == 1
        assert result["b"] == "x"

    def test_nested_dict(self):
        result = dict(_flatten_json({"outer": {"inner": 42}}))
        assert result.get("outer.inner") == 42

    def test_list_items(self):
        pairs = list(_flatten_json([{"id": 1}, {"id": 2}]))
        values = [v for _, v in pairs]
        assert 1 in values

    def test_depth_limit_respected(self):
        # _flatten_json stops at depth > 5, so 7-level deep nesting is truncated
        very_deep = {"a": {"b": {"c": {"d": {"e": {"f": {"g": "tooDeep"}}}}}}}
        pairs = list(_flatten_json(very_deep))
        keys = [k for k, _ in pairs]
        # "a.b.c.d.e.f.g" (6 dots) should not be produced
        assert not any(k.count('.') >= 6 for k in keys)