"""Wrapper for ffuf HTTP virtual host fuzzing."""

from __future__ import annotations

import re
from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import VhostResult

_DEFAULT_FILTER_CODES = {404, 400}

_LINE_RE = re.compile(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)")


def _parse_ffuf_line(
    line: str,
    domain: str,
    filter_codes: set[int],
) -> VhostResult | None:
    """Parse a single ffuf stdout line into a :class:`~subdomainenum.models.VhostResult`.

    :param line: A single line from ffuf human-readable stdout.
    :param domain: Base domain used to construct the vhost FQDN.
    :param filter_codes: HTTP status codes to exclude.
    :returns: A :class:`~subdomainenum.models.VhostResult` if the line is a match,
        ``None`` otherwise.
    :rtype: VhostResult | None
    """
    m = _LINE_RE.match(line)
    if not m:
        return None
    fuzz_word, status_str, size_str = m.group(1), m.group(2), m.group(3)
    status_code = int(status_str)
    if status_code in filter_codes:
        return None
    return VhostResult(
        vhost=f"{fuzz_word}.{domain}",
        status_code=status_code,
        content_length=int(size_str),
    )


def run_ffuf(
    domain: str,
    *,
    url: str,
    wordlist: str,
    threads: int = 40,
    timeout: int = 300,
    filter_codes: set[int] | None = None,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> list[VhostResult]:
    """Run ffuf to fuzz virtual hosts via the Host header.

    Each word from *wordlist* is substituted as ``FUZZ`` in the Host header
    value ``FUZZ.<domain>``.  ffuf's human-readable stdout is captured line by
    line; match lines are parsed directly via regex.  Non-match lines (header
    block, progress, summary) are forwarded to *line_cb* but produce no results.

    :param domain: Target base domain (used to build Host header values).
    :param url: Target URL (e.g. ``"http://10.0.0.1"``).
    :param wordlist: Absolute path to a vhost wordlist.
    :param threads: Number of concurrent threads.
    :param timeout: Maximum seconds to wait for ffuf.
    :param filter_codes: HTTP status codes to exclude from results.
        Defaults to ``{404, 400}``.
    :param line_cb: Optional callback invoked with each output line (for debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :returns: List of :class:`~subdomainenum.models.VhostResult` with
        non-filtered status codes.
    :rtype: list[VhostResult]
    """
    if filter_codes is None:
        filter_codes = _DEFAULT_FILTER_CODES

    cmd = [
        "ffuf",
        "-w", wordlist,
        "-u", url,
        "-H", f"Host: FUZZ.{domain}",
        "-t", str(threads),
        "-fc", ",".join(str(c) for c in sorted(filter_codes)),
        "-ac",
        "-noninteractive",
    ]

    try:
        lines, _ = run_tool(cmd, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb,
                            ignore_returncode=True, capture_stderr=True)
    except RuntimeError:
        return []

    return [r for line in lines if (r := _parse_ffuf_line(line, domain, filter_codes)) is not None]
