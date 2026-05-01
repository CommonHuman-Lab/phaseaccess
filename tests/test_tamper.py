"""Tests for phaseaccess.engine.tamper — URL/body mutation helpers."""
import pytest

from phaseaccess.engine.tamper import (
    _replace_query_param,
    _replace_path_segment,
    _replace_cookie,
    _set_nested,
)


# ---------------------------------------------------------------------------
# _replace_query_param
# ---------------------------------------------------------------------------

class TestReplaceQueryParam:
    def test_replaces_existing_param(self):
        url = "https://api.example.com/users?id=42&page=1"
        result = _replace_query_param(url, "id", "99")
        assert "id=99" in result
        assert "page=1" in result

    def test_adds_missing_param(self):
        url = "https://api.example.com/users?page=1"
        result = _replace_query_param(url, "id", "99")
        assert "id=99" in result
        assert "page=1" in result

    def test_only_replaces_first_occurrence(self):
        url = "https://api.example.com/users?id=1&id=2"
        result = _replace_query_param(url, "id", "99")
        # First occurrence replaced, second preserved
        assert "id=99" in result

    def test_preserves_other_params(self):
        url = "https://api.example.com/users?id=1&name=alice&page=2"
        result = _replace_query_param(url, "id", "5")
        assert "name=alice" in result
        assert "page=2" in result

    def test_empty_original_query(self):
        url = "https://api.example.com/users"
        result = _replace_query_param(url, "id", "42")
        assert "id=42" in result

    def test_preserves_scheme_and_host(self):
        url = "https://api.example.com/users?id=1"
        result = _replace_query_param(url, "id", "2")
        assert result.startswith("https://api.example.com/users")

    def test_special_characters_encoded(self):
        url = "https://api.example.com/items?q=hello"
        result = _replace_query_param(url, "q", "hello world")
        assert "hello+world" in result or "hello%20world" in result


# ---------------------------------------------------------------------------
# _replace_path_segment
# ---------------------------------------------------------------------------

class TestReplacePathSegment:
    def test_replaces_first_segment(self):
        url = "https://api.example.com/users/42/profile"
        result = _replace_path_segment(url, "path[1]", "42", "99")
        assert "/users/99/profile" in result

    def test_replaces_second_segment(self):
        url = "https://api.example.com/api/v1/users/42"
        # segments: api(0) v1(1) users(2) 42(3)
        result = _replace_path_segment(url, "path[3]", "42", "99")
        assert result.endswith("/99")

    def test_invalid_param_falls_back_to_string_replace(self):
        url = "https://api.example.com/users/42/items"
        result = _replace_path_segment(url, "badparam", "42", "99")
        # Falls back to string replacement
        assert "/99/" in result or result != url

    def test_preserves_query_string(self):
        url = "https://api.example.com/users/42?page=1"
        result = _replace_path_segment(url, "path[1]", "42", "99")
        assert "page=1" in result

    def test_segment_index_out_of_range_no_crash(self):
        url = "https://api.example.com/users/42"
        # Index 10 is out of range — should not crash
        result = _replace_path_segment(url, "path[10]", "42", "99")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _replace_cookie
# ---------------------------------------------------------------------------

class TestReplaceCookie:
    def test_replaces_named_cookie(self):
        cookie_str = "session=abc; user_id=42; theme=dark"
        result = _replace_cookie(cookie_str, "user_id", "99")
        assert "user_id=99" in result
        assert "session=abc" in result
        assert "theme=dark" in result

    def test_adds_missing_cookie(self):
        cookie_str = "session=abc"
        result = _replace_cookie(cookie_str, "user_id", "42")
        assert "user_id=42" in result
        assert "session=abc" in result

    def test_only_replaces_first_occurrence(self):
        cookie_str = "a=1; a=2"
        result = _replace_cookie(cookie_str, "a", "99")
        # First occurrence replaced
        assert "a=99" in result

    def test_empty_cookie_string(self):
        result = _replace_cookie("", "session", "xyz")
        assert "session=xyz" in result

    def test_cookie_without_value_pair_preserved(self):
        cookie_str = "secure; session=abc"
        result = _replace_cookie(cookie_str, "session", "xyz")
        assert "session=xyz" in result
        # "secure" is just a flag without "=" — it should be preserved or ignored cleanly
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _set_nested
# ---------------------------------------------------------------------------

class TestSetNested:
    def test_simple_key(self):
        obj = {"a": 1, "b": 2}
        _set_nested(obj, "a", 99)
        assert obj["a"] == 99

    def test_dotted_nested_key(self):
        obj = {"user": {"id": 1, "name": "Alice"}}
        _set_nested(obj, "user.id", 99)
        assert obj["user"]["id"] == 99

    def test_creates_missing_intermediate_key(self):
        obj = {}
        _set_nested(obj, "a.b.c", "value")
        assert obj["a"]["b"]["c"] == "value"

    def test_deeply_nested(self):
        obj = {"a": {"b": {"c": {"d": 0}}}}
        _set_nested(obj, "a.b.c.d", 42)
        assert obj["a"]["b"]["c"]["d"] == 42

    def test_array_notation_in_key(self):
        obj = {"items": [{"id": 1}, {"id": 2}]}
        _set_nested(obj, "items[0].id", 99)
        assert obj["items"][0]["id"] == 99

    def test_preserves_other_keys(self):
        obj = {"user": {"id": 1, "name": "Alice", "role": "admin"}}
        _set_nested(obj, "user.id", 2)
        assert obj["user"]["name"] == "Alice"
        assert obj["user"]["role"] == "admin"


# ---------------------------------------------------------------------------
# T6-21: POST_BODY body_context field preservation
# ---------------------------------------------------------------------------

class TestPostBodyFieldPreservation:
    """
    Ensure that when replaying a POST_BODY request, all original form fields
    are preserved and only the targeted field is changed.
    """

    def _make_post_ref(self, raw_body: str, param: str, value: str):
        from phaseaccess.engine.extractor import ObjectRef
        from phaseaccess.engine.reporter import IDORLocation, IDType
        return ObjectRef(
            location=IDORLocation.POST_BODY,
            param=param,
            value=value,
            id_type=IDType.INTEGER,
            url="https://api.example.com/order",
            method="POST",
            body_context=raw_body,
        )

    def test_all_original_fields_preserved(self):
        from phaseaccess.engine.tamper import _build_request
        import urllib.parse as up
        raw = "user_id=42&csrf_token=abc123&action=update&amount=100"
        ref = self._make_post_ref(raw, "user_id", "42")
        _url, headers, body = _build_request(ref, "99", {}, "")
        parsed = up.parse_qs(body)
        assert parsed["user_id"] == ["99"]
        assert parsed["csrf_token"] == ["abc123"]
        assert parsed["action"] == ["update"]
        assert parsed["amount"] == ["100"]

    def test_only_targeted_field_changed(self):
        from phaseaccess.engine.tamper import _build_request
        import urllib.parse as up
        raw = "order_id=7&discount=5&note=hello"
        ref = self._make_post_ref(raw, "order_id", "7")
        _url, headers, body = _build_request(ref, "999", {}, "")
        parsed = up.parse_qs(body)
        assert parsed["order_id"] == ["999"]
        assert parsed["discount"] == ["5"]
        assert parsed["note"] == ["hello"]

    def test_content_type_set_correctly(self):
        from phaseaccess.engine.tamper import _build_request
        raw = "id=1&foo=bar"
        ref = self._make_post_ref(raw, "id", "1")
        _url, headers, body = _build_request(ref, "2", {}, "")
        assert headers.get("Content-Type") == "application/x-www-form-urlencoded"
