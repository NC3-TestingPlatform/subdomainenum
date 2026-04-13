"""Wrapper for dnsrecon DNS enumeration tool."""

from __future__ import annotations

from typing import Callable

from subdomainenum.checks.active.tool_runner import run_tool
from subdomainenum.models import SourceResult

# Types that require only a domain (no wordlist).
_PASSIVE_TYPES = "std,srv,axfr,crt,zonewalk,bing,yand"

# Types that require a wordlist via -D.
_WORDLIST_TYPES = "brt,snoop"


def run_dnsrecon(
    domain: str,
    *,
    wordlist: str,
    timeout: int = 300,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Run dnsrecon for *domain* covering all applicable enumeration types.

    Two subprocess invocations are made:

    1. Non-wordlist types (``std,srv,axfr,crt,zonewalk,bing,yand``) — no ``-D``
       flag required.
    2. Wordlist-dependent types (``brt,snoop``) — uses *wordlist* via ``-D``.

    Results from both invocations are merged and deduplicated into a single
    :class:`~subdomainenum.models.SourceResult`.

    Excluded types:
    - ``rvl`` — requires an IP range (``-r``), not applicable here.
    - ``tld`` — tests TLD variations, not subdomain discovery.

    :param domain: Target base domain.
    :param wordlist: Absolute path to the wordlist file (used for brt/snoop).
    :param timeout: Maximum seconds to wait *per invocation*.
    :param line_cb: Optional callback invoked with each output line (debug mode).
    :param cmd_cb: Optional callback invoked once per command before launch.
    :rtype: SourceResult
    """
    result = SourceResult(name="dnsrecon")
    suffix = f".{domain}"
    all_lines: list[str] = []

    # --- Invocation 1: non-wordlist types ---
    cmd1 = [
        "dnsrecon",
        "-d", domain,
        "-t", _PASSIVE_TYPES,
        "--lifetime", "3",
    ]
    try:
        lines1 = run_tool(cmd1, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb)
        all_lines.extend(lines1)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    # --- Invocation 2: wordlist-dependent types ---
    cmd2 = [
        "dnsrecon",
        "-d", domain,
        "-D", wordlist,
        "-t", _WORDLIST_TYPES,
        "--lifetime", "3",
    ]
    try:
        lines2 = run_tool(cmd2, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb)
        all_lines.extend(lines2)
    except RuntimeError as exc:
        # Non-fatal: passive types already ran; record the error but keep results.
        result.error = str(exc)

    # Parse FQDNs from merged output.
    # dnsrecon outputs lines like: "[*] A sub.example.com 1.2.3.4"
    for line in all_lines:
        parts = line.split()
        for part in parts:
            part = part.lower()
            if part == domain or part.endswith(suffix):
                if part not in result.subdomains:
                    result.subdomains.append(part)

    return result
