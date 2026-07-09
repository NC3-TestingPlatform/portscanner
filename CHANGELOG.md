# Changelog

All notable changes to **portscanner** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

- Remaining Tier 2 items: per-host port targeting (scan each host only for its
  own rustscan-discovered ports, instead of the global union), and IPv6 (`-6`) /
  UDP (`-sU`) support.

---

## [0.5.1] — 2026-07-09

### Added
- GitHub Actions CI (`.github/workflows/ci.yml`): runs `ruff check` and the test
  suite on Python 3.11/3.12/3.13. Scanners are mocked, so CI needs no binaries.
- `Dockerfile` (+ `.dockerignore`): image bundling nmap and (best-effort)
  rustscan plus the package; connect-scan only, so no extra capabilities needed.
- Explicit `[tool.ruff]` config in `pyproject.toml`; `ruff` added to the `dev`
  extra so `ruff check` is reproducible.

## [0.5.0] — 2026-07-09

### Added
- `--scripts` / `-sC`: run nmap's default NSE scripts. Results surface per port
  in the Rich report and in `--json` (new `scripts` list on each port).
  `assess()` gains a keyword-only `scripts` parameter.
- Service CPEs are now captured. nmap2json drops the `<cpe>` child elements, so
  `parse_nmap_xml` re-walks the XML and attaches them; `ServiceInfo.cpe` is
  populated again (and appears in `--json`).

## [0.4.3] — 2026-07-09

### Fixed
- `--rustscan`: the nmap phase now forces `-Pn`. rustscan already established
  liveness by completing a TCP connect to open ports, but nmap re-ran host
  discovery and marked ping-blocking (firewalled) hosts "down", silently
  skipping their service scan — exactly the hosts two-phase mode targets.
- Targets beginning with `-` (e.g. `-oX`, `--script`, `-iL`) are now rejected.
  They would otherwise be consumed by nmap/rustscan as flags rather than
  targets (argument injection), notably via `--target-file` content.
- `defusedxml`'s own guard exceptions (e.g. entity/DTD forbidden) are now mapped
  to a `RuntimeError` instead of escaping — the defended case for hostile
  service banners embedded in nmap XML.
- Ctrl-C during a scan now exits cleanly with code 130 instead of a traceback.

### Removed
- Dropped two vestigial, never-populated fields: `ServiceInfo.cpe` (always `[]`)
  and `ScanReport.error` (always `None`; the `error` key is gone from `--json`).
  CPE metadata will return, actually populated, in a later release.

## [0.4.2] — 2026-07-09

### Fixed
- Docs: the `Changelog` project URL in `pyproject.toml` pointed at `blob/master`
  (the default branch is `main`) and 404'd — now `blob/main`.

### Changed
- Docs: refreshed the `cli.py` module docstring to cover multiple targets,
  `--target-file`, and `--rustscan`; corrected stale `CLAUDE.md` notes (the
  `info` command lists nmap *and* rustscan; generic test-count guidance).

## [0.4.1] — 2026-07-09

### Fixed
- Targets that resolve to the same IP (e.g. two DNS names for one server) are
  no longer reported as separate hosts. nmap emits one host block per target,
  so those blocks are now coalesced by address — hostnames and ports are
  unioned — giving one host entry and accurate summary counts instead of
  double-counting (previously "2 hosts / 6 open ports" for a single host).
  Hosts with no address are never coalesced together.

### Changed
- The timed-out banner now reads "warning: scan timed out …" (plain text
  instead of a warning glyph).

## [0.4.0] — 2026-07-09

### Changed
- Replaced the masscan fast-discovery phase with **rustscan**. rustscan sweeps
  all ports quickly with a TCP connect scan (**no root required**, unlike
  masscan) and resolves hostnames itself, then nmap runs service detection only
  on the ports rustscan reported open.

### Added
- `--rustscan` flag plus `--rustscan-batch`, `--rustscan-timeout` (per-port ms),
  `--rustscan-ports` (discovery range), and `--rustscan-ulimit`.
- `assess()` gains keyword-only `rustscan`, `rustscan_batch`, `rustscan_timeout`,
  `rustscan_ports`, and `rustscan_ulimit` parameters.
- New `portscanner/rustscan_utils.py` I/O boundary (greppable `-g` run + parse).

### Removed
- `--masscan`, `--masscan-rate`, `--masscan-ports` CLI flags and the
  `masscan`/`masscan_rate`/`masscan_ports` `assess()` parameters.
- `portscanner/masscan_utils.py`; `masscan` removed from the tool registry
  (`rustscan` added).

### Fixed
- `--json` output is no longer word-wrapped: a long (two-phase) command line
  could be wrapped mid-string, injecting a newline into a JSON string value and
  producing invalid JSON. JSON is now emitted with wrapping disabled.

## [0.3.0] — 2026-07-09

### Added
- `--masscan`: optional two-phase fast scan. masscan sweeps the port range
  (full range by default) to discover open ports, then nmap runs service/
  version detection **only** on the union of ports masscan reported open —
  much faster than nmap sweeping a wide range itself. Requires root /
  `CAP_NET_RAW` for masscan.
- `--masscan-rate` (packets/sec, default 1000) and `--masscan-ports`
  (discovery range, default `1-65535`) to tune the masscan phase.
- `assess()` gains keyword-only `masscan`, `masscan_rate`, and `masscan_ports`
  parameters.
- `masscan` added to the tool registry shown by `portscanner info`; new
  `portscanner/masscan_utils.py` I/O boundary (hostname→IP resolution, masscan
  subprocess, `-oL` parsing).

### Notes
- `--masscan` cannot be combined with `--ports`/`--top-ports` (use
  `--masscan-ports` for the discovery range).
- Hostname targets are resolved to IPs for masscan (which scans IPs/CIDRs, not
  names); nmap still runs against the original targets.
- A non-zero masscan exit (e.g. missing privileges) raises an error rather than
  being reported as "no open ports".

## [0.2.0] — 2026-07-09

### Added
- Multiple targets per scan: `portscanner check host1 host2 10.0.0.0/24`
  accepts any number of targets, all handed to a single nmap invocation.
- `--target-file` / `-iL`: read targets from a file (one or more per line;
  blank lines and `#` comments ignored). File targets are merged with any
  given on the command line and de-duplicated.
- `assess()` now accepts a single target string **or** an iterable of targets
  as its first argument, plus a keyword-only `target_file` parameter.

### Changed
- `ScanReport.target` (single string) is now a read-only property; the scanned
  targets are stored in the new `ScanReport.targets` list. JSON output gains a
  `targets` array while keeping the `target` string for backward compatibility.
- Passing a single target string to `assess()` still works unchanged.

## [0.1.0] — 2026-07-09

### Added
- Initial release: nmap-driven port and service inventory.
- CLI `portscanner check <target>` for a host, IP, or CIDR range, plus
  `portscanner info` (tool availability) and `--version` / `-V`.
- Default scan profile: TCP connect scan (`-sT`) with service/version
  detection (`-sV`) and timing template `-T4` — runs without root.
- Scope and tuning flags: `--ports` / `-p`, `--top-ports`, `--timing`,
  `--host-timeout`, `--max-retries`, `--skip-ping` (`-Pn`), `--no-service`,
  and `--timeout`.
- Public API `assess(target, *, ...) -> ScanReport` with keyword-only options
  and a `progress_cb` hook.
- nmap XML parsing via the [nmap2json](https://github.com/D4-project/nmap2json)
  library, hardened with `defusedxml`. Per-host and per-port `hsh256` hashes
  from nmap2json are surfaced for diffing scans across runs.
- Output: Rich tables, `--json` machine-readable output, and `--output`
  saving to `.txt` / `.svg` / `.html`.
- Test suite (60 tests) with I/O mocked at the `run_scan` / `subprocess.run`
  boundary.

[Unreleased]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/NC3-TestingPlatform/portscanner/releases/tag/v0.1.0
