"""Tests for active tool wrappers (subfinder, amass, findomain, assetfinder,
dnsrecon, gobuster_dns, wfuzz)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from subdomainenum.checks.active.amass import run_amass
from subdomainenum.checks.active.assetfinder import run_assetfinder
from subdomainenum.checks.active.dnsrecon import run_dnsrecon
from subdomainenum.checks.active.findomain import run_findomain
from subdomainenum.checks.active.gobuster_dns import run_gobuster_dns
from subdomainenum.checks.active.subfinder import run_subfinder
from subdomainenum.checks.active.wfuzz import run_wfuzz
from subdomainenum.models import SourceResult, VhostResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_run_tool(output: list[str]) -> patch:
    return patch("subdomainenum.checks.active.tool_runner.run_tool", return_value=output)


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------


class TestRunSubfinder:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.subfinder.run_tool", return_value=["sub.example.com"]):
            result = run_subfinder("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "subfinder"

    def test_command_contains_domain_and_silent(self) -> None:
        with patch("subdomainenum.checks.active.subfinder.run_tool", return_value=[]) as mock:
            run_subfinder("example.com")
            cmd = mock.call_args[0][0]
        assert "example.com" in cmd
        assert "-silent" in cmd
        assert "-passive" not in cmd

    def test_tool_missing_sets_available_false(self) -> None:
        with patch(
            "subdomainenum.checks.active.subfinder.run_tool",
            side_effect=RuntimeError("subfinder not found"),
        ):
            result = run_subfinder("example.com")
        assert result.available is False
        assert result.error is not None

    def test_parses_subdomains(self) -> None:
        with patch(
            "subdomainenum.checks.active.subfinder.run_tool",
            return_value=["a.example.com", "b.example.com"],
        ):
            result = run_subfinder("example.com")
        assert "a.example.com" in result.subdomains

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.checks.active.subfinder.run_tool", return_value=[]) as mock:
            run_subfinder("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------


class TestRunAmass:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.amass.run_tool", return_value=[]):
            result = run_amass("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "amass"

    def test_command_contains_enum_and_domain(self) -> None:
        with patch("subdomainenum.checks.active.amass.run_tool", return_value=[]) as mock:
            run_amass("example.com")
            cmd = mock.call_args[0][0]
        assert "enum" in cmd
        assert "example.com" in cmd
        # -passive is deprecated; amass passive is the default
        assert "-passive" not in cmd

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.amass.run_tool",
            side_effect=RuntimeError("amass not found"),
        ):
            result = run_amass("example.com")
        assert result.available is False

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.checks.active.amass.run_tool", return_value=[]) as mock:
            run_amass("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# findomain
# ---------------------------------------------------------------------------


class TestRunFindomain:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.findomain.run_tool", return_value=[]):
            result = run_findomain("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "findomain"

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.findomain.run_tool",
            side_effect=RuntimeError("findomain not found"),
        ):
            result = run_findomain("example.com")
        assert result.available is False

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.checks.active.findomain.run_tool", return_value=[]) as mock:
            run_findomain("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# assetfinder
# ---------------------------------------------------------------------------


class TestRunAssetfinder:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.assetfinder.run_tool", return_value=[]):
            result = run_assetfinder("example.com")
        assert isinstance(result, SourceResult)
        assert result.name == "assetfinder"

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.assetfinder.run_tool",
            side_effect=RuntimeError("assetfinder not found"),
        ):
            result = run_assetfinder("example.com")
        assert result.available is False

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.checks.active.assetfinder.run_tool", return_value=[]) as mock:
            run_assetfinder("example.com", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# dnsrecon
# ---------------------------------------------------------------------------


class TestRunDnsrecon:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.dnsrecon.run_tool", return_value=[]):
            result = run_dnsrecon("example.com", wordlist="/tmp/words.txt")
        assert isinstance(result, SourceResult)
        assert result.name == "dnsrecon"

    def test_two_invocations_are_made(self) -> None:
        with patch("subdomainenum.checks.active.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", wordlist="/tmp/words.txt")
        assert mock.call_count == 2

    def test_first_invocation_uses_passive_types(self) -> None:
        with patch("subdomainenum.checks.active.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", wordlist="/tmp/words.txt")
            first_cmd = mock.call_args_list[0][0][0]
        assert "-t" in first_cmd
        type_val = first_cmd[first_cmd.index("-t") + 1]
        assert "std" in type_val
        assert "axfr" in type_val
        assert "crt" in type_val
        # wordlist-only types must not be in the first invocation
        assert "brt" not in type_val
        assert "snoop" not in type_val
        # wordlist flag must not appear in first invocation
        assert "-D" not in first_cmd

    def test_second_invocation_uses_wordlist_types(self) -> None:
        with patch("subdomainenum.checks.active.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", wordlist="/tmp/subdomains.txt")
            second_cmd = mock.call_args_list[1][0][0]
        assert "-D" in second_cmd
        assert "/tmp/subdomains.txt" in second_cmd
        type_val = second_cmd[second_cmd.index("-t") + 1]
        assert "brt" in type_val
        assert "snoop" in type_val

    def test_tool_missing_sets_available_false(self) -> None:
        with patch(
            "subdomainenum.checks.active.dnsrecon.run_tool",
            side_effect=RuntimeError("dnsrecon not found"),
        ):
            result = run_dnsrecon("example.com", wordlist="/tmp/w.txt")
        assert result.available is False

    def test_parses_output_from_first_invocation(self) -> None:
        with patch(
            "subdomainenum.checks.active.dnsrecon.run_tool",
            side_effect=[["[*] A std.example.com 1.2.3.4"], []],
        ):
            result = run_dnsrecon("example.com", wordlist="/tmp/w.txt")
        assert "std.example.com" in result.subdomains

    def test_parses_output_from_second_invocation(self) -> None:
        with patch(
            "subdomainenum.checks.active.dnsrecon.run_tool",
            side_effect=[[], ["[*] A brt.example.com 1.2.3.4"]],
        ):
            result = run_dnsrecon("example.com", wordlist="/tmp/w.txt")
        assert "brt.example.com" in result.subdomains

    def test_merges_results_from_both_invocations(self) -> None:
        with patch(
            "subdomainenum.checks.active.dnsrecon.run_tool",
            side_effect=[
                ["[*] A a.example.com 1.1.1.1"],
                ["[*] A b.example.com 2.2.2.2"],
            ],
        ):
            result = run_dnsrecon("example.com", wordlist="/tmp/w.txt")
        assert "a.example.com" in result.subdomains
        assert "b.example.com" in result.subdomains

    def test_deduplicates_subdomains_across_invocations(self) -> None:
        with patch(
            "subdomainenum.checks.active.dnsrecon.run_tool",
            side_effect=[
                ["[*] A dup.example.com 1.1.1.1"],
                ["[*] A dup.example.com 1.1.1.1"],
            ],
        ):
            result = run_dnsrecon("example.com", wordlist="/tmp/w.txt")
        assert result.subdomains.count("dup.example.com") == 1

    def test_second_invocation_error_is_non_fatal(self) -> None:
        """First invocation succeeds; second fails — results from first are kept."""
        with patch(
            "subdomainenum.checks.active.dnsrecon.run_tool",
            side_effect=[
                ["[*] A ok.example.com 1.1.1.1"],
                RuntimeError("timeout"),
            ],
        ):
            result = run_dnsrecon("example.com", wordlist="/tmp/w.txt")
        assert result.available is True
        assert "ok.example.com" in result.subdomains
        assert result.error is not None

    def test_cmd_cb_passed_to_both_invocations(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.checks.active.dnsrecon.run_tool", return_value=[]) as mock:
            run_dnsrecon("example.com", wordlist="/tmp/w.txt", cmd_cb=cb)
        for call in mock.call_args_list:
            assert call.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# gobuster_dns
# ---------------------------------------------------------------------------


class TestRunGobusterDns:
    def test_returns_source_result(self) -> None:
        with patch("subdomainenum.checks.active.gobuster_dns.run_tool", return_value=[]):
            result = run_gobuster_dns("example.com", wordlist="/tmp/words.txt")
        assert isinstance(result, SourceResult)
        assert result.name == "gobuster"

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.checks.active.gobuster_dns.run_tool", return_value=[]) as mock:
            run_gobuster_dns("example.com", wordlist="/tmp/dns.txt")
            cmd = mock.call_args[0][0]
        assert "/tmp/dns.txt" in cmd

    def test_tool_missing(self) -> None:
        with patch(
            "subdomainenum.checks.active.gobuster_dns.run_tool",
            side_effect=RuntimeError("gobuster not found"),
        ):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert result.available is False

    def test_parses_found_lines(self) -> None:
        output = ["Found: sub.example.com"]
        with patch("subdomainenum.checks.active.gobuster_dns.run_tool", return_value=output):
            result = run_gobuster_dns("example.com", wordlist="/tmp/w.txt")
        assert "sub.example.com" in result.subdomains

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.checks.active.gobuster_dns.run_tool", return_value=[]) as mock:
            run_gobuster_dns("example.com", wordlist="/tmp/w.txt", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb


# ---------------------------------------------------------------------------
# wfuzz (vhost fuzzing)
# ---------------------------------------------------------------------------


class TestRunWfuzz:
    def test_returns_list_of_vhost_results(self) -> None:
        raw_output = [
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
            '000000002:   404        5 L       12 W       200 Ch     "nope"',
        ]
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert isinstance(results, list)

    def test_filters_404_by_default(self) -> None:
        raw_output = [
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
            '000000002:   404        5 L       12 W       200 Ch     "nope"',
        ]
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        vhosts = [r.vhost for r in results]
        assert not any("nope" in v for v in vhosts)

    def test_returns_vhost_result_objects(self) -> None:
        raw_output = ['000000001:   200        42 L      102 W      1024 Ch     "admin"']
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=raw_output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        if results:
            assert isinstance(results[0], VhostResult)

    def test_tool_missing_returns_empty_list(self) -> None:
        with patch(
            "subdomainenum.checks.active.wfuzz.run_tool",
            side_effect=RuntimeError("wfuzz not found"),
        ):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert results == []

    def test_wordlist_in_command(self) -> None:
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=[]) as mock:
            run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/vhosts.txt")
            cmd = mock.call_args[0][0]
        assert "/tmp/vhosts.txt" in cmd

    def test_skips_non_matching_lines(self) -> None:
        """Cover line 67: `continue` when regex does not match."""
        output = [
            "This is a header line with no wfuzz pattern",
            '000000001:   200        42 L      102 W      1024 Ch     "admin"',
        ]
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=output):
            results = run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt")
        assert len(results) == 1

    def test_cmd_cb_passed_to_run_tool(self) -> None:
        cb = lambda cmd: None
        with patch("subdomainenum.checks.active.wfuzz.run_tool", return_value=[]) as mock:
            run_wfuzz("example.com", url="http://example.com", wordlist="/tmp/w.txt", cmd_cb=cb)
        assert mock.call_args.kwargs.get("cmd_cb") is cb
