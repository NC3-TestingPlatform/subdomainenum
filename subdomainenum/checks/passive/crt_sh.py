"""Query the crt.sh Certificate Transparency database for subdomains via JSON API.

Uses the crt.sh HTTP JSON endpoint (``https://crt.sh/?q=%.domain&output=json``)
which is more stable than the direct PostgreSQL replica, whose PgBouncer
connection pooler rejects session-state commands and whose backend processes
terminate abnormally under certain query patterns.
"""

from __future__ import annotations

from typing import Callable

import requests

from subdomainenum.models import SourceResult

_BASE_URL = "https://crt.sh/"
_TIMEOUT = 30  # seconds

_CURL_CMD_TEMPLATE = "curl -s 'https://crt.sh/?q=%.{domain}&output=json'"


def query_crt_sh(
    domain: str,
    *,
    cmd_cb: Callable[[str], None] | None = None,
) -> SourceResult:
    """Query the crt.sh JSON API for certificates issued for *domain*.

    Wildcard entries (``*.example.com``) are skipped.  Multi-value
    ``name_value`` fields (newline-separated) are split.  Only entries that
    end with ``.{domain}`` or equal ``domain`` are kept.

    :param domain: Base domain to query (e.g. ``"example.com"``).
    :param cmd_cb: Optional callback invoked once with an equivalent curl command label.
    :returns: :class:`~subdomainenum.models.SourceResult` with ``name="crt.sh"``.
    :rtype: SourceResult
    """
    result = SourceResult(name="crt.sh")

    if cmd_cb is not None:
        cmd_cb(_CURL_CMD_TEMPLATE.format(domain=domain))

    try:
        resp = requests.get(
            _BASE_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        records = resp.json()
    except Exception as exc:
        result.error = str(exc)
        return result

    seen: set[str] = set()
    suffix = f".{domain}"
    for record in records:
        name_value = record.get("name_value", "")
        if not name_value:
            continue
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if not name or name.startswith("*"):
                continue
            if name == domain or name.endswith(suffix):
                if name not in seen:
                    seen.add(name)
                    result.subdomains.append(name)

    return result
