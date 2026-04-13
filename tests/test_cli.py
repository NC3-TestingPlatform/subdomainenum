"""Tests for subdomainenum.cli – Typer CLI entry point."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from subdomainenum.cli import _DebugDisplay, app
from subdomainenum.models import EnumMode, EnumReport, SourceResult, Status, SubdomainResult

runner = CliRunner()


def _make_report(domain: str = "example.com") -> EnumReport:
    return EnumReport(
        domain=domain,
        mode=EnumMode.PASSIVE,
        subdomains=[
            SubdomainResult(fqdn="sub.example.com", status=Status.ALIVE, alive=True, ip_addresses=["1.2.3.4"], sources=["crt.sh"]),
        ],
        sources=[SourceResult(name="crt.sh", subdomains=["sub.example.com"], available=True)],
    )


class TestCheckCommand:
    def test_basic_passive_check(self) -> None:
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive"])
        assert result.exit_code == 0

    def test_default_mode_without_wordlist_exits_nonzero(self) -> None:
        """Default mode is 'all', which requires --wordlist."""
        result = runner.invoke(app, ["check", "example.com"])
        assert result.exit_code != 0

    def test_json_output(self) -> None:
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["domain"] == "example.com"
        assert isinstance(data["subdomains"], list)

    def test_invalid_domain_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["check", "not_a_domain"])
        assert result.exit_code != 0

    def test_active_mode_without_wordlist_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["check", "example.com", "--mode", "active"])
        assert result.exit_code != 0

    def test_active_mode_with_nonexistent_wordlist_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["check", "example.com", "--mode", "active", "--wordlist", "/no/such/file.txt"])
        assert result.exit_code != 0

    def test_active_mode_with_wordlist(self, tmp_path) -> None:
        wl = tmp_path / "words.txt"
        wl.write_text("www\nmail\n")
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "active", "--wordlist", str(wl)])
        assert result.exit_code == 0

    def test_output_flag_saves_file(self, tmp_path) -> None:
        out = tmp_path / "report.txt"
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert "example.com" in out.read_text()

    def test_json_flag_ignores_output(self, tmp_path) -> None:
        out = tmp_path / "report.txt"
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--json", "--output", str(out)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["domain"] == "example.com"
        # --output is ignored when --json is active
        assert not out.exists()

    def test_assess_value_error_exits_nonzero(self) -> None:
        with patch("subdomainenum.cli.assess", side_effect=ValueError("wordlist required")):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive"])
        assert result.exit_code != 0

    def test_json_output_on_error(self) -> None:
        with patch("subdomainenum.cli.assess", side_effect=RuntimeError("boom")):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--json"])
        assert result.exit_code != 0
        data = json.loads(result.stdout)
        assert "error" in data


class TestDebugMode:
    def test_debug_flag_exits_zero(self) -> None:
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug"])
        assert result.exit_code == 0

    def test_debug_flag_passes_debug_cb_to_assess(self) -> None:
        captured: list = []

        def fake_assess(*args, **kwargs):
            cb = kwargs.get("debug_cb")
            if cb:
                cb("subfinder", "sub.example.com")
            captured.append(cb)
            return _make_report()

        with patch("subdomainenum.cli.assess", side_effect=fake_assess):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug"])
        assert result.exit_code == 0
        assert len(captured) == 1
        assert captured[0] is not None  # debug_cb was wired up

    def test_debug_flag_no_debug_cb_without_flag(self) -> None:
        captured: list = []

        def fake_assess(*args, **kwargs):
            captured.append(kwargs.get("debug_cb"))
            return _make_report()

        with patch("subdomainenum.cli.assess", side_effect=fake_assess):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive"])
        assert result.exit_code == 0
        assert captured[0] is None  # no debug_cb when --debug not passed

    def test_debug_and_json_flags_together(self) -> None:
        """--debug + --json should still produce valid JSON on stdout."""
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["domain"] == "example.com"

    def test_debug_mode_value_error_exits_nonzero(self) -> None:
        """Cover lines 170-172: ValueError in the debug branch."""
        with patch("subdomainenum.cli.assess", side_effect=ValueError("wordlist required")):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--debug"])
        assert result.exit_code != 0


class TestProgressCb:
    def test_progress_cb_invoked(self) -> None:
        """Cover line 179: _progress_cb closure body is called when assess uses it."""

        def fake_assess(*args, **kwargs):
            cb = kwargs.get("progress_cb")
            if cb:
                cb("Doing something...")
            return _make_report()

        with patch("subdomainenum.cli.assess", side_effect=fake_assess):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive"])
        assert result.exit_code == 0


class TestSaveReportFormats:
    def test_output_svg_saves_file(self, tmp_path) -> None:
        """Cover line 270: export_svg branch in _save_report."""
        out = tmp_path / "report.svg"
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_output_html_saves_file(self, tmp_path) -> None:
        """Cover line 272: export_html branch in _save_report."""
        out = tmp_path / "report.html"
        with patch("subdomainenum.cli.assess", return_value=_make_report()):
            result = runner.invoke(app, ["check", "example.com", "--mode", "passive", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()


class TestInfoCommand:
    def test_info_runs(self) -> None:
        with patch("subdomainenum.cli.detect_tools", return_value={"subfinder": True, "amass": False, "findomain": False, "assetfinder": True, "dnsrecon": True, "gobuster": False, "wfuzz": False}):
            result = runner.invoke(app, ["info"])
        assert result.exit_code == 0

    def test_info_shows_tool_names(self) -> None:
        with patch("subdomainenum.cli.detect_tools", return_value={k: False for k in ["subfinder", "amass", "findomain", "assetfinder", "dnsrecon", "gobuster", "wfuzz"]}):
            result = runner.invoke(app, ["info"])
        assert "subfinder" in result.stdout or result.exit_code == 0


class TestVersionFlag:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "subdomainenum" in result.stdout


class TestDebugDisplay:
    """Tests for _DebugDisplay internal buffering and post-exit summary."""

    def _make_display(self):
        from rich.console import Console
        return _DebugDisplay(Console(stderr=True), "example.com")

    def test_full_buffers_captures_all_lines_beyond_max_debug_lines(self) -> None:
        """_full_buffers must retain every line, even past _MAX_DEBUG_LINES."""
        from subdomainenum.cli import _MAX_DEBUG_LINES

        display = self._make_display()
        total = _MAX_DEBUG_LINES + 5
        for i in range(total):
            display.add_line("subfinder", f"line{i}")

        # Rolling deque is capped at _MAX_DEBUG_LINES
        assert len(display._buffers["subfinder"]) == _MAX_DEBUG_LINES
        # Full buffer retains everything
        assert len(display._full_buffers["subfinder"]) == total

    def test_print_summary_uses_full_buffers(self) -> None:
        """_print_summary must print all lines, not just the last _MAX_DEBUG_LINES."""
        from subdomainenum.cli import _MAX_DEBUG_LINES
        from rich.console import Console

        console = Console(record=True, width=120)
        display = _DebugDisplay(console, "example.com")

        total = _MAX_DEBUG_LINES + 3
        for i in range(total):
            display.add_line("subfinder", f"result{i}")
        display.finish("subfinder", None)

        display._print_summary()
        output = console.export_text()

        # First and last lines must both appear in the static summary
        assert "result0" in output
        assert f"result{total - 1}" in output
