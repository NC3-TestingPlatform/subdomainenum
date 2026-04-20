"""Wrapper for dnsrecon DNS enumeration tool."""

from __future__ import annotations

import os
from typing import Callable

from subdomainenum.tools.tool_runner import run_tool
from subdomainenum.models import EnumMode, ToolResult

# Passive enumeration types (no wordlist required):
#   std — SOA, NS, A, AAAA, MX, SRV (standard DNS records)
#   srv — SRV record enumeration
# Extended with boolean flags: -b (Bing), -y (Yandex), -k (crt.sh)
_PASSIVE_TYPES = "std,srv"

# Optional passive type (requires -D wordlist):
#   snoop — cache-snoop the domain's authoritative NS for entries in the
#   wordlist. dnsrecon derives the NS automatically from the target domain
#   when -n is absent, so no resolver argument needs to be plumbed in.
_PASSIVE_SNOOP_TYPE = "snoop"

# Active enumeration types (require -D wordlist):
#   brt — brute-force subdomain/host names using -D wordlist
# Extended with boolean flags: -a (AXFR), -z (DNSSEC zone walk)
_ACTIVE_TYPES = "brt"

# dnsrecon consults SHODAN_API_KEY as the fallback for --shodan-key. When the
# env var is present we enable --shodan and --shodan-active during passive
# enumeration to enrich netblocks discovered via -s (SPF reverse) and -w
# (whois). No CLI flag is exposed in subdomainenum — the enrichment is
# opt-in purely via the environment.
_SHODAN_ENV_VAR = "SHODAN_API_KEY"


def run_dnsrecon(
    domain: str,
    *,
    mode: EnumMode = EnumMode.ALL,
    wordlist: str | None = None,
    timeout: int = 300,
    threads: int | None = None,
    filter_wildcard: bool = True,
    disable_check_nxdomain: bool = False,
    disable_check_recursion: bool = False,
    disable_check_bindversion: bool = False,
    line_cb: Callable[[str], None] | None = None,
    cmd_cb: Callable[[str], None] | None = None,
) -> ToolResult:
    """Run dnsrecon for *domain* using the enumeration types appropriate for *mode*.

    Mode behaviour:

    - ``passive`` — ``-t std,srv`` with Bing (``-b``), Yandex (``-y``), crt.sh
      (``-k``), SPF reverse lookup (``-s``), and deep whois (``-w``) flags; no
      wordlist required. When a wordlist *is* supplied, ``snoop`` is added to
      the types so the domain's authoritative NS is cache-snooped for each
      wordlist entry (dnsrecon auto-derives the NS from the domain). When the
      ``SHODAN_API_KEY`` environment variable is set, ``--shodan`` and
      ``--shodan-active`` are added to enrich netblocks discovered via ``-s``
      and ``-w``.
    - ``active`` — ``-t brt`` with AXFR (``-a``), DNSSEC zone walk (``-z``), and
      wildcard filter (``-f``) flags; requires a wordlist.
    - ``all`` — combines passive and active type sets (including ``snoop``,
      since a wordlist is mandatory) and all flags; Shodan enrichment is also
      enabled when ``SHODAN_API_KEY`` is set.

    Excluded:
    - ``rvl`` — requires ``-r`` IP range, not available here
    - ``tld`` — tests TLD variations, not subdomain discovery

    :param domain: Target base domain.
    :param mode: Enumeration mode controlling which types and flags are used.
    :param wordlist: Path to the wordlist file. Required for active/all modes;
        optional for passive mode, where it unlocks ``snoop`` cache snooping.
    :param timeout: Maximum seconds to wait for dnsrecon.
    :param threads: Number of threads for dnsrecon (``--threads``). ``None`` uses the dnsrecon default.
    :param filter_wildcard: Only applies in active and all modes. When ``True`` (default), pass
        ``-f`` to filter wildcard records from brute-force output. When ``False``, pass ``--iw``
        to continue brute-forcing even if a wildcard record is detected. The two flags are
        mutually exclusive. Has no effect in passive mode.
    :param disable_check_nxdomain: Pass ``--disable_check_nxdomain`` to skip NXDOMAIN hijack detection.
    :param disable_check_recursion: Pass ``--disable_check_recursion`` to skip recursion checks.
    :param disable_check_bindversion: Pass ``--disable_check_bindversion`` to skip BIND version checks.
    :param line_cb: Optional callback invoked with each output line (debug mode).
    :param cmd_cb: Optional callback invoked once with the full command string before launch.
    :rtype: ToolResult
    """
    result = ToolResult(name="dnsrecon")

    # When a wordlist is present we can unlock snoop in passive paths; the
    # command only receives -D once, even though snoop (passive) and brt
    # (active) both need it.
    has_wordlist = bool(wordlist)

    if mode == EnumMode.PASSIVE:
        types = (
            f"{_PASSIVE_TYPES},{_PASSIVE_SNOOP_TYPE}" if has_wordlist else _PASSIVE_TYPES
        )
        use_passive_flags = True
        use_active_flags = False
        use_wordlist = has_wordlist
    elif mode == EnumMode.ACTIVE:
        types = _ACTIVE_TYPES
        use_passive_flags = False
        use_active_flags = True
        use_wordlist = True
    else:  # ALL — wordlist is mandatory, so snoop is always on
        types = f"{_PASSIVE_TYPES},{_PASSIVE_SNOOP_TYPE},{_ACTIVE_TYPES}"
        use_passive_flags = True
        use_active_flags = True
        use_wordlist = True

    cmd = ["dnsrecon", "-d", domain, "-t", types, "--lifetime", "3"]

    if use_wordlist and wordlist:
        cmd += ["-D", wordlist]

    if threads is not None:
        cmd += ["--threads", str(threads)]

    if disable_check_nxdomain:
        cmd += ["--disable_check_nxdomain"]
    if disable_check_recursion:
        cmd += ["--disable_check_recursion"]
    if disable_check_bindversion:
        cmd += ["--disable_check_bindversion"]

    if use_passive_flags:
        cmd += ["-b", "-y", "-k", "-s", "-w"]  # Bing, Yandex, crt.sh, SPF reverse, deep whois
        # Shodan enrichment is opt-in via env var; dnsrecon itself reads
        # SHODAN_API_KEY when --shodan-key is omitted, so we don't have to
        # forward the secret on the command line.
        if os.environ.get(_SHODAN_ENV_VAR, "").strip():
            cmd += ["--shodan", "--shodan-active"]

    if use_active_flags:
        cmd += ["-a", "-z"]  # AXFR zone transfer, DNSSEC zone walk
        if filter_wildcard:
            cmd += ["-f"]  # filter wildcard records from brute-force output
        else:
            cmd += ["--iw"]  # continue brute-forcing even if wildcard detected

    try:
        lines, timed_out = run_tool(cmd, timeout=timeout, line_cb=line_cb, cmd_cb=cmd_cb, capture_stderr=True, ignore_returncode=True)
    except RuntimeError as exc:
        result.available = False
        result.error = str(exc)
        return result

    # dnsrecon outputs lines like: "[*] A sub.example.com 1.2.3.4"
    suffix = f".{domain}"
    for line in lines:
        parts = line.split()
        for part in parts:
            part = part.lower()
            if part == domain or part.endswith(suffix):
                if part not in result.subdomains:
                    result.subdomains.append(part)

    result.timed_out = timed_out
    return result
