# portscanner

> nmap-driven port and service inventory for any host, IP, or CIDR range —
> from the command line or as a Python library.

**portscanner** runs an nmap scan, parses the XML output with
[nmap2json](https://github.com/D4-project/nmap2json), and prints a
colour-coded inventory of open ports and detected services. It is
*inventory only* — it reports what is exposed without assigning a letter
grade or severity.

```
$ portscanner check scanme.nmap.org
```

![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)
![Tests](https://img.shields.io/badge/tests-102%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)
![License](https://img.shields.io/badge/license-GPLv3-lightgrey)

Part of the [NC3-TestingPlatform](https://github.com/NC3-TestingPlatform).

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [External Tools](#external-tools)
- [CLI Usage](#cli-usage)
- [Python API](#python-api)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)

---

## Features

| Capability | What it does |
| --- | --- |
| **Multiple targets** | Scan any number of targets in one run — on the command line and/or from a file (`--target-file` / `-iL`). |
| **Fast mode (`--rustscan`)** | Two-phase scan: rustscan sweeps all ports fast, then nmap runs service detection **only** on the ports rustscan found open. TCP connect scan — no root needed. |
| **Port scan** | TCP connect scan (`nmap -sT`) — no root required. |
| **Service/version detection** | On by default (`nmap -sV`); disable with `--no-service`. |
| **Scope control** | `--ports 22,80,443`, `--ports 1-1024`, or `--top-ports N`. |
| **Tuning** | `--timing 0-5` (`-T`), `--host-timeout`, `--max-retries`, `--skip-ping` (`-Pn`). |
| **Stable hashes** | Each host and port carries nmap2json's `hsh256` (stable across runs, timestamps excluded) for diffing scans over time. |
| **Output** | Rich tables, machine-readable `--json`, or saved `.txt` / `.svg` / `.html`. |

The scan pipeline is:

```
nmap -oX -  →  XML on stdout  →  nmap2json  →  typed models  →  report
```

XML is parsed with `defusedxml` (nmap embeds scanned service banners into its
output, so parsing is hardened against XXE / entity-expansion).

---

## Requirements

- Python ≥ 3.11
- [`nmap`](https://nmap.org) on `PATH` (required)
- [`rustscan`](https://github.com/RustScan/RustScan) on `PATH` — optional, only for `--rustscan` (no root needed)
- Python deps (installed automatically): `nmap2json`, `defusedxml`, `rich`, `typer`

---

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # editable install with test deps
```

Install nmap if it is missing:

```bash
apt install nmap      # Debian/Ubuntu
dnf install nmap      # Fedora/RHEL
brew install nmap     # macOS
```

Check availability at any time:

```bash
portscanner info
```

---

## External Tools

| Tool | Kind | Install |
| --- | --- | --- |
| `nmap` | PATH binary (required) | `apt install nmap` / `dnf install nmap` / `brew install nmap` |
| `rustscan` | PATH binary (optional, for `--rustscan`) | `cargo install rustscan` (or GitHub releases) — no root needed |
| `nmap2json` | Python dependency | installed via pip (not a PATH binary) |

---

## CLI Usage

```bash
# Default: TCP connect + version detection, nmap's top-1000 ports
portscanner check scanme.nmap.org

# Several targets in one run (hosts, IPs, CIDR ranges)
portscanner check scanme.nmap.org 10.0.0.1 192.168.1.0/24

# Targets from a file (one or more per line; blank lines and '#' comments ignored)
portscanner check --target-file targets.txt        # or -iL targets.txt
portscanner check extra.example --target-file targets.txt   # file + CLI targets merged

# A CIDR range, skipping host discovery, only the 100 most common ports
portscanner check 10.0.0.0/24 --top-ports 100 --skip-ping

# Fast mode: rustscan discovers open ports, nmap fingerprints only those (no root)
portscanner check 10.0.0.0/24 --rustscan
portscanner check scanme.nmap.org --rustscan --rustscan-ports 1-1000 --rustscan-batch 5000

# Explicit ports, gentler timing, JSON to stdout
portscanner check example.com -p 22,80,443 --timing 3 --json

# Bound per-host time and retries; save an HTML report
portscanner check host --host-timeout 30 --max-retries 2 --output report.html

# Show whether nmap is available
portscanner info

# Version
portscanner --version    # or -V
```

### Flags

| Flag | Meaning |
| --- | --- |
| `TARGETS...` | One or more targets (host / IP / CIDR). Optional when `--target-file` is given. |
| `-iL`, `--target-file` | Read targets from a file (one or more per line; blank lines and `#` comments ignored). Merged with CLI targets. |
| `-p`, `--ports` | nmap `-p` spec (e.g. `22,80,443` or `1-1024`). Mutually exclusive with `--top-ports`. |
| `--top-ports N` | Scan nmap's N most common ports. |
| `--timing N` | nmap timing template `0`–`5` (`-T`), default `4`. |
| `--host-timeout S` | Give up on a host after S seconds. |
| `--max-retries N` | Cap probe retransmissions. |
| `--skip-ping` | Skip host discovery, treat every host as up (`-Pn`). |
| `--no-service` | Disable service/version detection (`-sV` is on by default). |
| `--rustscan` | Fast two-phase scan: rustscan discovers open ports, then nmap fingerprints only those. No root; not combinable with `--ports`/`--top-ports`. |
| `--rustscan-batch N` | rustscan parallel batch size (`--batch-size`). |
| `--rustscan-timeout MS` | rustscan per-port timeout in milliseconds (`--timeout`). |
| `--rustscan-ports SPEC` | Discovery port spec rustscan sweeps (default: its full range). |
| `--rustscan-ulimit N` | File-descriptor limit rustscan requests (`--ulimit`); raising it speeds up full-range scans. |
| `--timeout S` | Per-process subprocess timeout in seconds (applied to the rustscan and nmap runs independently). |
| `--json` | Print machine-readable JSON instead of Rich tables. |
| `-o`, `--output` | Save report; format inferred from extension (`.txt` / `.svg` / `.html`). |
| `-V`, `--version` | Print version and exit. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Bad input / invalid arguments / cannot write output |
| `2` | Scan error (nmap missing, unparseable output, connection error) |

---

## Python API

```python
from portscanner.assessor import assess

# A single target, several targets, or a file — all supported
report = assess("scanme.nmap.org", top_ports=100, skip_ping=True)
report = assess(["10.0.0.1", "10.0.0.2"], ports="22,80,443")
report = assess([], target_file="targets.txt")

for host in report.hosts:
    for port in host.open_ports:
        svc = port.service.describe() if port.service else ""
        print(host.address, port.port, port.protocol, svc)
```

`assess()` returns a `ScanReport`. The first argument is a single target string
or an iterable of targets; all remaining parameters are keyword-only:

```python
assess(
    targets,               # str or iterable of str
    *,
    target_file=None,      # path to a file of targets (merged with `targets`)
    ports=None,            # "-p" spec
    top_ports=None,        # "--top-ports"
    timing=4,              # "-T<n>"
    host_timeout=None,     # "--host-timeout"
    max_retries=None,      # "--max-retries"
    skip_ping=False,       # "-Pn"
    service_detection=True,# "-sV"
    rustscan=False,        # two-phase rustscan→nmap discovery
    rustscan_batch=None,   # rustscan --batch-size
    rustscan_timeout=None, # rustscan per-port --timeout (ms)
    rustscan_ports=None,   # rustscan discovery range (default: full range)
    rustscan_ulimit=None,  # rustscan --ulimit
    timeout=300.0,         # per-process subprocess timeout (float)
    progress_cb=None,      # Callable[[str], None]
) -> ScanReport
```

Raises `ValueError` for bad input (empty target, invalid timing, mutually
exclusive scope flags) and `RuntimeError` if nmap is unavailable or its output
cannot be parsed.

---

## Project Structure

```
portscanner/
  cli.py          → Typer entry point; validation, flags, progress, output
  assessor.py     → Public API: assess(...) → ScanReport; dict→model conversion
  nmap_utils.py   → nmap I/O boundary: build_nmap_args(), run_scan(), parse_nmap_xml()
  rustscan_utils.py→ rustscan I/O boundary: build_rustscan_args(), run_scan_rustscan(), parse_rustscan_greppable()
  models.py       → HostState/PortState enums; ServiceInfo/PortResult/HostResult/ScanReport
  constants.py    → REQUIRED_TOOLS registry; detect_tools(); get_install_hint()
  reporter.py     → Rich renderers; to_dict(); save_report()
  verdict.py      → VerdictSummary dataclass + build_verdict() (pure, counts only)
tests/
  conftest.py     → synthetic nmap XML fixture + parsed/report fixtures
  test_*.py       → pytest; I/O mocked at run_scan / subprocess.run
```

---

## Running Tests

```bash
pytest                    # full suite with coverage
pytest --tb=short -q      # quick run
ruff check portscanner/   # lint
```

The test suite has **102 tests**. Network and subprocess I/O are mocked at the
`nmap_utils` / `rustscan_utils` / `subprocess.run` boundaries, so tests never
launch nmap or rustscan.
