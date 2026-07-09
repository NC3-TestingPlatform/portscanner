# portscanner — Project Instructions

## Tech Stack
| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | ≥ 3.11 |
| CLI framework | Typer | ≥ 0.12 |
| Terminal output | Rich | ≥ 13.7 |
| nmap XML → JSON | nmap2json | ≥ 2605.0 |
| Safe XML parsing | defusedxml | ≥ 0.7 |
| Testing | pytest + pytest-cov + pytest-mock | ≥ 8 / ≥ 5 / ≥ 3.12 |

External binaries: **nmap** (required, on `PATH`); **masscan** (optional, only
for `--masscan`; needs root / `CAP_NET_RAW`).

## Build & Run
```bash
pip install -e ".[dev]"                     # install in editable mode with dev deps
portscanner check scanme.nmap.org           # default scan (top-1000 TCP, -sT -sV)
portscanner check 10.0.0.0/24 --top-ports 100 --skip-ping
portscanner check example.com -p 22,80,443 --timing 3 --json
portscanner info                            # show nmap availability
pytest                                      # run tests with coverage
pytest --tb=short -q                        # quick run
```

## Project Structure
```
portscanner/
  cli.py          → Typer entry point; target validation, flags, progress, output
  assessor.py     → Public API: assess(...) → ScanReport; nmap2json dict → model conversion
  nmap_utils.py   → nmap I/O boundary: build_nmap_args(), build_command(), run_scan(), parse_nmap_xml(), read_targets_file()
  masscan_utils.py→ masscan I/O boundary: build_masscan_args(), resolve_targets(), run_scan_masscan(), parse_masscan_list()
  models.py       → HostState/PortState enums; ServiceInfo/PortResult/HostResult/ScanReport dataclasses
  constants.py    → REQUIRED_TOOLS registry; detect_tools(); get_install_hint(); defaults
  reporter.py     → Rich renderers; to_dict(); save_report()
  verdict.py      → VerdictSummary dataclass + build_verdict() (pure, counts only)
tests/
  conftest.py     → synthetic nmap XML + sample_hosts / sample_report fixtures
  test_*.py       → pytest, AAA pattern
```

## Architecture

### Request lifecycle
1. `cli.py` validates the target and flags, builds a `progress_cb`.
2. `cli.py` calls `assess(target, ...)` from `assessor.py`.
3. `assessor.py` builds the nmap argument list via `nmap_utils.build_nmap_args()`
   and calls `nmap_utils.run_scan()`.
4. `run_scan()` launches `nmap -oX - <target>`, captures the XML on stdout, and
   parses it via `parse_nmap_xml()` (defusedxml → nmap2json's core converter).
5. `assessor.py` converts the nmap2json host dicts into typed `ScanReport`
   models (`_to_host` / `_to_port` / `_to_service`).
6. `reporter.py` renders with Rich or serialises to JSON.

### nmap2json note
The released `nmap2json` (PyPI `2605.0`) ships a **broken** `nmap_xml_to_json(str)`
— it calls `.getroot()` on the `Element` that `ET.fromstring` returns. Only the
file-based `nmap_file_to_json` works. `parse_nmap_xml()` therefore parses the
string with `defusedxml`, wraps the root in an `ElementTree`, and calls the
library's core `nmap_to_json(tree)` directly. If a future release fixes the
string entry point, this can be simplified — but keep the defusedxml parse.

### masscan fast-discovery phase (`--masscan`)
When enabled, `assess()` first calls `masscan_utils.run_scan_masscan()` to sweep
the discovery range (`--masscan-ports`, default full range) and collect the union
of open ports across all hosts. nmap then runs with `-p <those ports>` only. If
masscan finds nothing, nmap is skipped and an empty-hosts report is returned. A
non-zero masscan exit raises `RuntimeError` (never a silent empty result).
`--masscan` is mutually exclusive with `--ports`/`--top-ports`. Hostnames are
resolved to IPs for masscan (it can't scan names); nmap keeps the original targets.

### I/O boundaries (mock these in tests)
| Boundary | Module | What to patch |
|----------|--------|---------------|
| nmap subprocess | `nmap_utils.py` | `nmap_utils.subprocess.run` (unit) or `assessor.run_scan` (integration) |
| masscan subprocess | `masscan_utils.py` | `masscan_utils.subprocess.run` + `masscan_utils.resolve_targets` (unit) or `assessor.run_scan_masscan` (integration) |

Never mock `assess()` itself in library tests. `cli.py` tests may patch
`portscanner.cli.assess` to exercise CLI wiring in isolation.

## Scan profile
- Base is always a TCP connect scan (`-sT`) so no root is required.
- Service/version detection (`-sV`) is on by default (`--no-service` disables it).
- Timing defaults to `-T4`. `--host-timeout`, `--max-retries`, and `--skip-ping`
  (`-Pn`) map straight through to nmap.
- `--ports` and `--top-ports` are mutually exclusive; neither → nmap's top-1000.
- Multiple targets (CLI args and/or `--target-file` / `-iL`) are merged,
  validated against `constants.TARGET_RE`, de-duplicated by `_collect_targets()`
  in `assessor.py`, and handed to a **single** nmap invocation.

## Scoring
**Inventory only — no letter grade, no severity.** Per the platform convention,
letter grades are reserved for `mailvalidator` and `headersvalidator`.
`verdict.build_verdict()` returns pure counts (hosts up/down, open ports,
services identified). Do not add grading.

## Testing Conventions
- Mock at the I/O boundary in the table above — never mock `assess()`.
- Use `mocker` (pytest-mock) or `unittest.mock.patch`.
- AAA pattern: Arrange → Act → Assert.
- Coverage target: ≥ 80% (configured in `pyproject.toml`). Current: **96%**.
- Current test count: **96 tests**.

## Adding a scan option
1. Add the parameter to `nmap_utils.build_nmap_args()` (pure; emit flags in a
   stable order) and validate inputs there (raise `ValueError`).
2. Thread it through `assessor.assess()` as a keyword-only parameter.
3. Add a matching `typer.Option` in `cli.py check`.
4. Cover it in `tests/test_nmap_utils.py` (arg building) and, if it changes the
   report, `tests/test_assessor.py`.

## Conventions
- `from __future__ import annotations` at the top of every module.
- `logger = logging.getLogger("portscanner")` declared **after all imports**.
- Keyword-only params after the first positional (`*,`); `timeout` is `float`.
- Use `X | None` (PEP 604), never `Optional[X]` in signatures.
- Sphinx-style docstrings: `:param:`, `:returns:`, `:rtype:`.
- `--version` short flag is `-V` (uppercase), never `-v`.
- `save_report()` raises `ValueError` for unknown extensions — no silent fallback.
- Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`.

## Before Every Commit
```bash
pytest --tb=short -q          # tests pass at coverage target
ruff check portscanner/       # lint clean
```
- Update **CHANGELOG.md** (`## [Unreleased]`, or move to `## [x.y.z] — YYYY-MM-DD` on a bump).
- If the test count changed, update the README badge + "60 tests" sentence and the count in this file.
- On a version bump, update **both** `pyproject.toml` and `portscanner/__init__.py` (the fallback `__version__`), then tag `vX.Y.Z` and create the GitHub release with `--notes-file`.

## Version Bumping (semver)
- **patch** (`0.1.x`) — bug fixes, refactor, docs, lint.
- **minor** (`0.x.0`) — new scan option, new CLI flag, new output.
- **major** (`x.0.0`) — breaking `assess()` signature or report-field change.
