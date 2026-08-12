# Changelog

All notable changes to **subdomainenum** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Removed

- `.tours/new-joiner-architecture.tour` — the checked-in CodeTour walkthrough.
  Eleven of its thirteen file anchors pointed at unrelated lines (`assess()` had
  moved from line 222 to 463; `_run_passive` had been renamed `_run_passive_enum`
  and `fqdn_sources` `tool_map`), and its `ref` field still named the retired
  `master` branch, so every step opened files from a stale revision. Tours are
  now maintained locally rather than in the repo.

### Changed

- `CLAUDE.md` — corrected the Code Tours guidance. It previously stated that
  line-number drift needed no tour update because "tours reference landmarks,
  not exact lines"; CodeTour `line` fields are exact, and that guidance is what
  allowed the anchors above to rot unnoticed. Added a validation snippet.

---

## [0.14.3] — 2026-07-08

### Changed
- `assessor.assess()`: ffuf vhost fuzzing no longer waits for the passive and
  active enumeration pools to fully drain before starting. It now runs a
  "wave 1" pass concurrently with enumeration against whatever target is
  already known (an explicit `--url`, or the base domain's own resolved
  IP(s)) — the common single-IP case. A "wave 2" pass (usually empty) fuzzes
  any additional IPs only discoverable via enumeration (passive FQDNs /
  gobuster hits) once the pools drain. This removes ffuf from the critical
  path in `active`/`all` modes and can substantially cut total scan time for
  large wordlists. Report output (`vhosts`, `tools`) is unchanged — results
  across both waves are deduplicated by vhost name before being merged.
- `assessor`: dnsrecon is now invoked with an explicit `--threads 30` (was
  unset, falling back to dnsrecon's low internal default). Speeds up the
  parallelizable lookups (Bing/Yandex/SPF reverse); the sequential
  AXFR / DNSSEC NSEC zone-walk passes (`-a`/`-z`) are unaffected and keep
  their full coverage.
- `assessor`: ffuf's "wave 2" fan-out (bonus IPs discovered via enumeration,
  beyond the primary wave-1 target) now runs with a 90s per-URL timeout
  instead of the 300s default. A single enumeration-discovered IP that is
  unreachable from the scanner (e.g. a DNS record pointing at a CGNAT or
  VPN-mesh address) previously hung for the full 5-minute timeout and could
  dominate total scan time; observed legitimate wave-2 targets finish in
  well under a minute. Wave 1 keeps the full 300s budget.
- `tools.dnsrecon`: dropped the `-k` (crt.sh) flag from dnsrecon's
  invocation. subfinder already queries crt.sh as one of its built-in
  sources (concurrently, in the same passive pool), and dnsrecon's own
  crt.sh client hardcodes an unconfigurable retry policy (20 attempts, up
  to 60s backoff between tries) that can burn a large chunk of the passive
  phase's wall-clock whenever crt.sh — a free, frequently-overloaded,
  unauthenticated service — returns 502/503/429 or times out. No coverage
  is lost; this removes duplicated, unreliable work.

---

## [0.14.2] — 2026-05-15

### Changed
- `assessor` and `dns_utils`: `logger = logging.getLogger("subdomainenum")`
  moved below all imports to comply with E402 (module-level import order).
- `cli`: network errors (any non-`ValueError` exception from `assess()`) now
  exit with code `2`; `ValueError` (e.g. missing wordlist) exits `1`.
- `reporter`: `print_report()` renamed to `print_full_report()` for
  consistency with all other platform modules. `Console` created with
  `highlight=False`. `save_report()` now raises `ValueError` for unsupported
  file extensions instead of silently falling back to plain text.

### Removed
- `reporter.print_report` deprecated alias removed; use `print_full_report` directly.

---

## [0.14.1] — 2026-05-15

### Changed
- `__init__`: version fallback now catches `PackageNotFoundError` explicitly
  instead of bare `Exception`, consistent with all other platform modules.
- `reporter`: exposes a public `console` alias (`Console(record=True)`) and
  a `save_report(path)` function supporting `.txt`, `.svg`, and `.html`
  extensions (unknown extensions fall back to plain text); the old JSON-only
  `save_report(report, path)` signature has been replaced.
- CLI migrated to use `reporter.console` and `reporter.save_report()` —
  the private `_save_report()` helper in `cli.py` has been removed.

---

## [0.14.0] — 2026-04-27

### Added
- **Streaming DNS resolver** (`StreamingResolver`) — resolves FQDNs in the
  background as each tool wrapper parses them; avoids a full post-scan batch
  and speeds up large enumerations.
- **`--debug-log` flag** — collects per-tool raw output to an auto-named log
  file (`<domain>_YYYYMMDD_HHMMSS.log`); written to `/reports/` if mounted,
  otherwise to the current directory.
- **Docker Compose support** — multi-stage Dockerfile builds all Go tools
  (subfinder, findomain, assetfinder, gobuster, ffuf) in stage 1; installs
  the Python package in stage 2.
- **Phase fusion** (`all` mode) — passive and active-enum pools run
  concurrently under an outer executor, reducing total wall-clock time.
- **ffuf fanout** — multiple target URLs fuzzed in parallel (capped at 8
  workers); passive-phase resolved IPs reused for URL enrichment to avoid
  duplicate lookups.
- CodeTour walkthrough (`.tours/new-joiner-architecture.tour`) — end-to-end
  request lifecycle for new contributors.

### Changed
- Repository moved to the
  [NC3-TestingPlatform](https://github.com/NC3-TestingPlatform) GitHub
  organisation; all internal URLs updated.
- Active-enum pool is always **gobuster** (1 worker); dnsrecon moved
  permanently to the passive phase (AXFR + DNSSEC zone walk target public
  authoritative nameservers).
- Per-FQDN `A` and `AAAA` queries fan out on a shared 256-worker pool so the
  slower query bounds per-FQDN latency.

### Removed
- amass removed from all enumeration phases.

---

## [0.1.0] — 2026-04-13

### Added
- Initial release of **subdomainenum**.
- Passive enumeration: subfinder, findomain, assetfinder, dnsrecon
  (`std,srv` with Bing/Yandex/crt.sh/SPF/AXFR/DNSSEC zone walk).
- Active enumeration: gobuster DNS (brute-force), ffuf vhost discovery.
- CLI: `subdomainenum check <domain>` with `--mode`, `--wordlist`, `--url`,
  `--json`, `--output` flags.
- `subdomainenum info` — shows installed tool availability and install hints.
- Report export to `.txt`, `.svg`, `.html`.
- Missing external tools auto-skipped via `constants.detect_tools()`.

---

[Unreleased]: https://github.com/NC3-TestingPlatform/subdomainenum/compare/v0.14.3...HEAD
[0.14.3]: https://github.com/NC3-TestingPlatform/subdomainenum/compare/v0.14.2...v0.14.3
[0.14.2]: https://github.com/NC3-TestingPlatform/subdomainenum/compare/v0.14.1...v0.14.2
[0.14.1]: https://github.com/NC3-TestingPlatform/subdomainenum/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/NC3-TestingPlatform/subdomainenum/compare/v0.1.0...v0.14.0
[0.1.0]: https://github.com/NC3-TestingPlatform/subdomainenum/releases/tag/v0.1.0
