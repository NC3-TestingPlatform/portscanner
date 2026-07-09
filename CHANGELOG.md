# Changelog

All notable changes to **portscanner** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

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

[Unreleased]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/NC3-TestingPlatform/portscanner/releases/tag/v0.1.0
