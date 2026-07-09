"""portscanner CLI – nmap-driven port/service inventory.

Sub-commands
------------
check   Run an nmap scan for a target and print the inventory report.
info    Show whether nmap is available and how to install it.

Usage example::

    portscanner check scanme.nmap.org
    portscanner check 10.0.0.0/24 --top-ports 100 --skip-ping
    portscanner check example.com -p 22,80,443 --timing 3 --json
    portscanner check host --host-timeout 30 --max-retries 2 --output report.html
    portscanner info
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from portscanner import __version__
from portscanner.assessor import assess
from portscanner.constants import (
    DEFAULT_TIMEOUT,
    DEFAULT_TIMING,
    REQUIRED_TOOLS,
    TARGET_RE,
    detect_tools,
    get_install_hint,
)
from portscanner.reporter import console, print_full_report, save_report, to_dict

app = typer.Typer(
    name="portscanner",
    help="nmap-driven port and service inventory for a target host, IP, or range.",
    add_completion=False,
)

_err = Console(stderr=True)


def _validate_target(value: str) -> str:
    value = value.strip()
    if not value or not TARGET_RE.match(value):
        raise typer.BadParameter(f"Invalid target: {value!r}")
    return value


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"portscanner {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Print version and exit.",
        ),
    ] = False,
) -> None:
    pass


# ---------------------------------------------------------------------------
# check command
# ---------------------------------------------------------------------------


@app.command()
def check(
    targets: Annotated[
        Optional[list[str]],
        typer.Argument(
            help="One or more targets — host, IP, or CIDR range (e.g. scanme.nmap.org 10.0.0.0/24). Optional when --target-file is given.",
        ),
    ] = None,
    target_file: Annotated[
        Optional[str],
        typer.Option(
            "--target-file",
            "-iL",
            help="Read targets from a file (one or more per line; blank lines and '#' comments ignored). Merged with any targets given on the command line.",
        ),
    ] = None,
    ports: Annotated[
        Optional[str],
        typer.Option(
            "--ports",
            "-p",
            help="Port spec passed to nmap -p (e.g. 22,80,443 or 1-1024). Mutually exclusive with --top-ports.",
        ),
    ] = None,
    top_ports: Annotated[
        Optional[int],
        typer.Option("--top-ports", help="Scan nmap's N most common ports. Mutually exclusive with --ports."),
    ] = None,
    timing: Annotated[
        int,
        typer.Option("--timing", help="nmap timing template 0–5 (-T<n>)."),
    ] = DEFAULT_TIMING,
    host_timeout: Annotated[
        Optional[float],
        typer.Option("--host-timeout", help="Give up on a host after this many seconds (--host-timeout)."),
    ] = None,
    max_retries: Annotated[
        Optional[int],
        typer.Option("--max-retries", help="Cap probe retransmissions (--max-retries)."),
    ] = None,
    skip_ping: Annotated[
        bool,
        typer.Option("--skip-ping", help="Skip host discovery and treat every host as online (-Pn)."),
    ] = False,
    no_service: Annotated[
        bool,
        typer.Option("--no-service", help="Disable service/version detection (-sV is on by default)."),
    ] = False,
    masscan: Annotated[
        bool,
        typer.Option(
            "--masscan",
            help="Fast two-phase scan: discover open ports with masscan (needs root/CAP_NET_RAW), then run nmap service detection only on those ports. Not combinable with --ports/--top-ports.",
        ),
    ] = False,
    masscan_rate: Annotated[
        Optional[int],
        typer.Option("--masscan-rate", help="masscan transmit rate in packets/sec (default 1000)."),
    ] = None,
    masscan_ports: Annotated[
        Optional[str],
        typer.Option("--masscan-ports", help="Port range masscan sweeps for discovery (default 1-65535)."),
    ] = None,
    output: Annotated[
        Optional[str],
        typer.Option(
            "--output",
            "-o",
            help=(
                "Save the report to a file. Format is inferred from the extension: "
                ".txt for plain text, .svg for SVG, .html for HTML."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print machine-readable JSON to stdout instead of Rich tables."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Overall subprocess timeout for the nmap run, in seconds."),
    ] = DEFAULT_TIMEOUT,
) -> None:
    """Run an nmap scan for TARGETS and display the port/service inventory."""
    targets = [_validate_target(t) for t in (targets or [])]

    if target_file and not Path(target_file).is_file():
        _err.print(f"[red]Error:[/red] target file not found: {target_file}")
        raise typer.Exit(code=1)

    if not targets and not target_file:
        _err.print("[red]Error:[/red] provide at least one target or --target-file.")
        raise typer.Exit(code=1)

    if ports and top_ports is not None:
        _err.print("[red]Error:[/red] --ports and --top-ports are mutually exclusive.")
        raise typer.Exit(code=1)

    scan_label = targets[0] if len(targets) == 1 and not target_file else "targets"

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=_err) as progress:
        task = progress.add_task(f"Scanning {scan_label}…", total=None)

        def _progress_cb(msg: str) -> None:
            progress.update(task, description=msg)

        try:
            report = assess(
                targets,
                target_file=target_file,
                ports=ports,
                top_ports=top_ports,
                timing=timing,
                host_timeout=host_timeout,
                max_retries=max_retries,
                skip_ping=skip_ping,
                service_detection=not no_service,
                masscan=masscan,
                masscan_rate=masscan_rate,
                masscan_ports=masscan_ports,
                timeout=timeout,
                progress_cb=_progress_cb,
            )
        except ValueError as exc:
            _err.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1)
        except Exception as exc:
            _err.print(f"[red]Connection/scan error:[/red] {exc}")
            raise typer.Exit(code=2)

    if json_output:
        _print_json(report)
        return

    print_full_report(report, console=console)

    if output:
        try:
            save_report(output)
            console.print(f"[dim]Report saved to[/dim] {output}")
        except (ValueError, OSError) as exc:
            _err.print(f"[red]Error:[/red] Cannot write to {output!r}: {exc}")
            raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# info command
# ---------------------------------------------------------------------------


@app.command()
def info() -> None:
    """Show whether the required external tools are available."""
    availability = detect_tools()

    table = Table("Tool", "Available", "Install hint", box=box.SIMPLE_HEAD)
    for name in sorted(REQUIRED_TOOLS):
        avail = availability.get(name, False)
        style = "green" if avail else "red"
        table.add_row(
            name,
            f"[{style}]{'yes' if avail else 'no'}[/{style}]",
            get_install_hint(name) if not avail else "",
        )
    console.print(table)
    console.print(
        "[dim]nmap is required; masscan is optional (only for --masscan, and needs "
        "root/CAP_NET_RAW). nmap2json is a Python dependency (pip), not a PATH binary.[/dim]"
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _print_json(report) -> None:
    """Serialise *report* to JSON and print it to stdout via the console.

    :param report: :class:`~portscanner.models.ScanReport` to serialise.
    """
    console.print(json.dumps(to_dict(report), indent=2))


if __name__ == "__main__":  # pragma: no cover
    app()
