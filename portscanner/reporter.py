"""Rich terminal rendering and JSON serialization for portscanner reports."""

from __future__ import annotations

import os

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from portscanner.models import HostResult, HostState, PortState, ScanReport
from portscanner.verdict import build_verdict

# Module-level console; record=True enables save_report() export.
# The public alias ``console`` is imported by cli.py so that all
# terminal output flows through the same recorded stream.
_console = Console(record=True, highlight=False)
console = _console


_SECTION_PANEL_KWARGS = dict(style="white", padding=(0, 1))
_TABLE_KWARGS = dict(
    box=box.ROUNDED,
    show_header=True,
    header_style="bold white",
    border_style="dim",
    expand=False,
    padding=(0, 1),
)


# ---------------------------------------------------------------------------
# JSON / dict serialization
# ---------------------------------------------------------------------------


def to_dict(report: ScanReport) -> dict:
    """Serialize *report* to a plain dictionary suitable for JSON output.

    :param report: Completed scan report.
    :returns: JSON-serializable dict.
    :rtype: dict
    """
    return {
        "target": report.target,
        "command": report.command,
        "timed_out": report.timed_out,
        "error": report.error,
        "hosts": [
            {
                "address": h.address,
                "hostnames": h.hostnames,
                "state": h.state.value,
                "reason": h.reason,
                "hsh256": h.hsh256,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state.value,
                        "reason": p.reason,
                        "hsh256": p.hsh256,
                        "service": None
                        if p.service is None
                        else {
                            "name": p.service.name,
                            "product": p.service.product,
                            "version": p.service.version,
                            "extrainfo": p.service.extrainfo,
                            "method": p.service.method,
                        },
                    }
                    for p in h.ports
                ],
            }
            for h in report.hosts
        ],
    }


# ---------------------------------------------------------------------------
# Rich rendering
# ---------------------------------------------------------------------------


def _host_state_style(state: HostState) -> str:
    return {
        HostState.UP: "green",
        HostState.DOWN: "red",
        HostState.UNKNOWN: "dim",
    }.get(state, "white")


def _port_state_style(state: PortState) -> str:
    return {
        PortState.OPEN: "green",
        PortState.CLOSED: "red",
        PortState.FILTERED: "yellow",
        PortState.OPEN_FILTERED: "yellow",
        PortState.CLOSED_FILTERED: "yellow",
        PortState.UNFILTERED: "yellow",
        PortState.UNKNOWN: "dim",
    }.get(state, "white")


def _host_panel(host: HostResult) -> Panel:
    """Render one host and its port inventory as a Rich :class:`Panel`."""
    title_bits = [host.address or "(unknown)"]
    if host.hostnames:
        title_bits.append(f"({', '.join(host.hostnames)})")
    title = " ".join(title_bits)

    state_style = _host_state_style(host.state)
    state_line = Text.from_markup(
        f"[dim]state:[/dim] [{state_style}]{host.state.value}[/{state_style}]"
    )

    if host.ports:
        table = Table(**_TABLE_KWARGS)
        table.add_column("Port", justify="right", no_wrap=True)
        table.add_column("Proto", no_wrap=True)
        table.add_column("State", no_wrap=True)
        table.add_column("Service", style="cyan")
        table.add_column("Version")
        for p in host.ports:
            svc = p.service
            table.add_row(
                str(p.port),
                p.protocol,
                Text(p.state.value, style=_port_state_style(p.state)),
                (svc.name if svc and svc.name else "—"),
                (svc.describe() if svc else "") or "—",
            )
        body = Group(state_line, table)
    else:
        body = Group(state_line, Text.from_markup("[dim]No ports reported.[/dim]"))

    return Panel(body, title=f"[bold]{title}[/bold]", **_SECTION_PANEL_KWARGS)


def print_full_report(report: ScanReport, *, console: Console | None = None) -> None:
    """Render the full scan report to the terminal using Rich.

    :param report: Completed scan report.
    :param console: Optional Rich :class:`~rich.console.Console` instance
        (defaults to the module-level console).
    """
    con = console or _console
    verdict = build_verdict(report)

    con.rule(f"[bold cyan]Port Scan Report — {report.target}[/bold cyan]")
    if report.command:
        con.print(f"  [dim]command:[/dim] {report.command}", highlight=False)
    if report.timed_out:
        con.print("  [yellow]⚠ scan timed out — results may be partial[/yellow]")
    if report.error:
        con.print(f"  [red]error:[/red] {report.error}")
    con.print()

    if report.hosts:
        for host in report.hosts:
            con.print(_host_panel(host))
    else:
        con.print(
            Panel(
                "[dim]No hosts reported by nmap.[/dim]",
                title="[bold]Hosts[/bold]",
                **_SECTION_PANEL_KWARGS,
            )
        )

    # Summary panel (counts only — no grading)
    summary_text = Text.from_markup(f"[bold]{verdict.summary_line}[/bold]")
    breakdown = Table(box=box.SIMPLE, show_header=False, expand=False, padding=(0, 1))
    breakdown.add_column(style="dim", no_wrap=True)
    breakdown.add_column()
    breakdown.add_row(
        "Hosts",
        f"{verdict.total_hosts} total · "
        f"[green]{verdict.hosts_up} up[/green] · "
        f"[red]{verdict.hosts_down} down[/red]",
    )
    breakdown.add_row(
        "Ports",
        f"[green]{verdict.total_open_ports} open[/green] · "
        f"{verdict.total_ports_reported} reported",
    )
    if verdict.services_identified:
        breakdown.add_row("Services", f"{verdict.services_identified} identified")

    con.print(
        Panel(
            Group(summary_text, breakdown),
            title="Summary",
            border_style="white",
            expand=False,
            padding=(0, 1),
        )
    )

    con.rule("[dim]End of Report[/dim]")


_FORMAT_BY_EXT: dict[str, str] = {
    ".txt": "text",
    ".text": "text",
    ".svg": "svg",
    ".html": "html",
    ".htm": "html",
}


def save_report(path: str) -> None:
    """Save the recorded console output to *path*.

    The export format is inferred from the file extension:

    * ``.txt`` / ``.text`` → plain text (no ANSI codes)
    * ``.svg``             → SVG image
    * ``.html`` / ``.htm`` → self-contained HTML page

    Must be called **after** :func:`print_full_report` because Rich only
    captures output when :class:`~rich.console.Console` is created with
    ``record=True``, which is already set on the module-level
    :data:`console` instance.

    :param path: Destination file path, e.g. ``"report.svg"``.
    :raises ValueError: If the extension is not one of the supported values.
    :raises OSError: If the file cannot be written.
    """
    ext = os.path.splitext(path)[1].lower()
    fmt = _FORMAT_BY_EXT.get(ext)
    if fmt is None:
        raise ValueError(
            f"Unsupported file extension {ext!r}. Use .txt, .svg, or .html."
        )
    if fmt == "svg":
        console.save_svg(path, clear=False)
    elif fmt == "html":
        console.save_html(path, clear=False)
    else:
        console.save_text(path, clear=False)
