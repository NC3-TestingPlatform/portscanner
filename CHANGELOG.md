# Changelog

All notable changes to **portscanner** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

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

[Unreleased]: https://github.com/NC3-TestingPlatform/portscanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NC3-TestingPlatform/portscanner/releases/tag/v0.1.0
