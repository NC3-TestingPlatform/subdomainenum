"""Tests for subdomainenum.checks.passive.crt_sh – crt.sh CT log query via JSON API."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from subdomainenum.checks.passive.crt_sh import query_crt_sh
from subdomainenum.models import SourceResult


def _make_response(records: list[dict], status_code: int = 200) -> MagicMock:
    """Return a mock requests.Response whose .json() returns *records*."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = records
    resp.raise_for_status.return_value = None
    return resp


class TestQueryCrtSh:
    def test_returns_source_result(self) -> None:
        resp = _make_response([{"name_value": "sub.example.com"}, {"name_value": "*.example.com"}])
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "crt.sh"

    def test_parses_subdomains(self) -> None:
        resp = _make_response([
            {"name_value": "mail.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com"},  # duplicate record
        ])
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert "mail.example.com" in result.subdomains
        assert "www.example.com" in result.subdomains
        assert result.subdomains.count("mail.example.com") == 1

    def test_strips_wildcard_prefix(self) -> None:
        resp = _make_response([{"name_value": "*.example.com"}])
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert "*.example.com" not in result.subdomains
        assert result.subdomains == []

    def test_handles_http_error(self) -> None:
        resp = _make_response([], status_code=500)
        resp.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert result.error is not None
        assert result.subdomains == []

    def test_handles_connection_error(self) -> None:
        with patch("requests.get", side_effect=requests.ConnectionError("timeout")):
            result = query_crt_sh("example.com")
        assert result.available is True  # passive/native source, always available
        assert result.error is not None
        assert result.subdomains == []

    def test_handles_json_decode_error(self) -> None:
        resp = _make_response([])
        resp.json.side_effect = ValueError("no JSON")
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert result.error is not None
        assert result.subdomains == []

    def test_multiple_records_deduplicated(self) -> None:
        resp = _make_response([
            {"name_value": "a.example.com"},
            {"name_value": "b.example.com"},
            {"name_value": "a.example.com"},  # duplicate
        ])
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert result.subdomains.count("a.example.com") == 1
        assert "b.example.com" in result.subdomains

    def test_filters_out_of_scope_domains(self) -> None:
        resp = _make_response([
            {"name_value": "sub.example.com"},
            {"name_value": "unrelated.com"},
        ])
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert "unrelated.com" not in result.subdomains
        assert "sub.example.com" in result.subdomains

    def test_handles_unexpected_exception(self) -> None:
        with patch("requests.get", side_effect=RuntimeError("unexpected")):
            result = query_crt_sh("example.com")
        assert result.error is not None
        assert "unexpected" in result.error
        assert result.subdomains == []

    def test_cmd_cb_called_with_curl_cmd(self) -> None:
        calls: list[str] = []
        resp = _make_response([])
        with patch("requests.get", return_value=resp):
            query_crt_sh("example.com", cmd_cb=calls.append)
        assert len(calls) == 1
        assert "crt.sh" in calls[0]
        assert "example.com" in calls[0]

    def test_cmd_cb_not_called_when_none(self) -> None:
        resp = _make_response([])
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com", cmd_cb=None)
        assert isinstance(result, SourceResult)

    def test_empty_name_value_record_skipped(self) -> None:
        resp = _make_response([{"name_value": ""}, {"name_value": "sub.example.com"}])
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert result.subdomains == ["sub.example.com"]

    def test_multiline_name_value_split(self) -> None:
        """name_value may contain newline-separated SANs from the same certificate."""
        resp = _make_response([
            {"name_value": "a.example.com\nb.example.com\n*.example.com"},
        ])
        with patch("requests.get", return_value=resp):
            result = query_crt_sh("example.com")
        assert "a.example.com" in result.subdomains
        assert "b.example.com" in result.subdomains
        assert "*.example.com" not in result.subdomains
