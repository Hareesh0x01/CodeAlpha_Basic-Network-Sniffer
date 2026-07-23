"""
CLI — Command-Line Interface & Interactive Menu
=================================================

Provides both a CLI argument parser (for advanced users) and an
interactive menu system (for beginners). This is the user-facing
entry point for all sniffer functionality.

"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from sniffer import __version__
from sniffer.utils.logger import get_logger

logger = get_logger(__name__)

# Global Rich console for consistent output
console = Console()


def parse_arguments(args: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Supports two subcommands:
    - ``capture``: Start capturing packets.
    - ``list-interfaces``: Show available network interfaces.

    If no subcommand is given, interactive mode is used.

    Args:
        args: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        A ``Namespace`` with all parsed arguments.

    Example:
        >>> args = parse_arguments(["capture", "--interface", "Wi-Fi", "--count", "100"])
        >>> args.interface
        'Wi-Fi'
        >>> args.count
        100
    """
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description=(
            "🔍 Basic Network Sniffer — Educational Packet Capture Tool\n"
            "Capture and analyze real network packets from your local machine."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m sniffer capture                          # Interactive mode\n"
            "  python -m sniffer capture --interface Wi-Fi        # Specify interface\n"
            '  python -m sniffer capture --filter "tcp port 80"   # HTTP traffic only\n'
            "  python -m sniffer capture --count 100 --json       # Capture 100, export JSON\n"
            "  python -m sniffer list-interfaces                  # Show available interfaces\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # ─── Global Options ─────────────────────────────────────────────────
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (INFO level logging).",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output (DEBUG level logging).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output.",
    )

    # ─── Subcommands ────────────────────────────────────────────────────
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Capture subcommand
    capture_parser = subparsers.add_parser(
        "capture",
        help="Start capturing packets.",
        description="Capture and analyze network packets in real-time.",
    )
    capture_parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Network interface to capture on (e.g., Wi-Fi, eth0).",
    )
    capture_parser.add_argument(
        "-f",
        "--filter",
        type=str,
        default="",
        help='BPF filter expression (e.g., "tcp port 80", "udp", "host 192.168.1.1").',
    )
    capture_parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited).",
    )
    capture_parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=0,
        help="Capture timeout in seconds (0 = no timeout).",
    )
    capture_parser.add_argument(
        "--csv",
        action="store_true",
        help="Export captured packets to CSV after stopping.",
    )
    capture_parser.add_argument(
        "--json",
        action="store_true",
        help="Export captured packets to JSON after stopping.",
    )
    capture_parser.add_argument(
        "--pcap",
        action="store_true",
        help="Export captured packets to PCAP after stopping.",
    )
    capture_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output file path for exports (auto-generated if not specified).",
    )

    # ─── Protocol Shortcut Flags ────────────────────────────────────────
    # These are convenience flags that auto-generate BPF filters.
    # They are mutually exclusive with --filter.
    proto_group = capture_parser.add_argument_group(
        "Protocol shortcuts",
        "Quick protocol filters (alternative to --filter).",
    )
    proto_group.add_argument(
        "--tcp",
        action="store_true",
        help="Capture only TCP traffic.",
    )
    proto_group.add_argument(
        "--udp",
        action="store_true",
        help="Capture only UDP traffic.",
    )
    proto_group.add_argument(
        "--dns",
        action="store_true",
        help="Capture only DNS traffic (UDP/TCP port 53).",
    )
    proto_group.add_argument(
        "--icmp",
        action="store_true",
        help="Capture only ICMP (ping) traffic.",
    )
    proto_group.add_argument(
        "--http",
        action="store_true",
        help="Capture only HTTP traffic (TCP port 80).",
    )
    proto_group.add_argument(
        "--arp",
        action="store_true",
        help="Capture only ARP traffic.",
    )

    # ─── Auto-Save Flags ────────────────────────────────────────────────
    auto_group = capture_parser.add_argument_group(
        "Auto-save",
        "Automatically save capture data when stopping.",
    )
    auto_group.add_argument(
        "--auto-pcap",
        action="store_true",
        help="Automatically save to PCAP when capture stops.",
    )
    auto_group.add_argument(
        "--auto-csv",
        action="store_true",
        help="Automatically save to CSV when capture stops.",
    )
    auto_group.add_argument(
        "--auto-json",
        action="store_true",
        help="Automatically save to JSON when capture stops.",
    )

    # ─── Statistics Flag ────────────────────────────────────────────────
    capture_parser.add_argument(
        "--stats",
        action="store_true",
        help="Show detailed protocol statistics after capture.",
    )

    # List-interfaces subcommand
    subparsers.add_parser(
        "list-interfaces",
        help="List available network interfaces.",
        description="Display all network interfaces on this system.",
    )

    parsed = parser.parse_args(args)

    # Ensure all required attributes exist on the parsed namespace
    # to prevent crashes in __main__.py if an argument is missing
    # due to the subcommand used.
    if not hasattr(parsed, "command") or not parsed.command:
        parsed.command = "capture"

    for attr in [
        "interface",
        "filter",
        "count",
        "timeout",
        "csv",
        "json",
        "pcap",
        "output",
        "tcp",
        "udp",
        "dns",
        "icmp",
        "http",
        "arp",
        "auto_pcap",
        "auto_csv",
        "auto_json",
        "stats",
    ]:
        if not hasattr(parsed, attr):
            setattr(
                parsed,
                attr,
                (
                    None
                    if attr in ["interface", "output"]
                    else (0 if attr in ["count", "timeout"] else False)
                ),
            )
        parsed.csv = False
        parsed.json = False
        parsed.pcap = False
        parsed.output = None
        parsed.tcp = False
        parsed.udp = False
        parsed.dns = False
        parsed.icmp = False
        parsed.http = False
        parsed.arp = False
        parsed.auto_pcap = False
        parsed.auto_csv = False
        parsed.auto_json = False
        parsed.stats = False

    # ─── Resolve Protocol Shortcut Flags to BPF Filter ──────────────────
    if parsed.command == "capture" and not getattr(parsed, "filter", ""):
        bpf_parts = []
        if getattr(parsed, "tcp", False):
            bpf_parts.append("tcp")
        if getattr(parsed, "udp", False):
            bpf_parts.append("udp")
        if getattr(parsed, "dns", False):
            bpf_parts.append("(udp port 53 or tcp port 53)")
        if getattr(parsed, "icmp", False):
            bpf_parts.append("icmp")
        if getattr(parsed, "http", False):
            bpf_parts.append("tcp port 80")
        if getattr(parsed, "arp", False):
            bpf_parts.append("arp")
        if bpf_parts:
            parsed.filter = " or ".join(bpf_parts)
            logger.info("Protocol shortcuts resolved to BPF: '%s'", parsed.filter)

    return parsed


def show_interfaces_table() -> None:
    """Display a formatted table of available network interfaces.

    Uses the ``InterfaceManager`` to discover interfaces and
    presents them in a Rich table with color-coded status.
    """
    from sniffer.core.interfaces import InterfaceManager

    console.print()
    console.print(
        "[bold bright_white]🖧  Available Network Interfaces[/bold bright_white]"
    )
    console.print()

    try:
        manager = InterfaceManager()
        interfaces = manager.list_interfaces(include_down=True)
    except Exception as exc:
        console.print(f"[bold red]Error discovering interfaces:[/bold red] {exc}")
        return

    if not interfaces:
        console.print("[yellow]No network interfaces found.[/yellow]")
        return

    table = Table(
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_blue",
    )
    table.add_column("#", style="bold", width=4, justify="right")
    table.add_column("Name", style="bold cyan")
    table.add_column("Description")
    table.add_column("IP Address", style="green")
    table.add_column("MAC Address", style="dim")
    table.add_column("Status", justify="center")

    for i, iface in enumerate(interfaces, 1):
        status_style = "bold green" if iface.is_up else "dim red"
        status_text = "● UP" if iface.is_up else "○ DOWN"
        name_suffix = " [dim](loopback)[/dim]" if iface.is_loopback else ""

        table.add_row(
            str(i),
            f"{iface.name}{name_suffix}",
            iface.description or "—",
            iface.ip_address,
            iface.mac_address,
            f"[{status_style}]{status_text}[/{status_style}]",
        )

    console.print(table)
    console.print()


def interactive_interface_selection() -> str:
    """Interactively prompt the user to select a network interface.

    Displays a numbered list of available interfaces and waits for
    the user to enter a number.

    Returns:
        The name of the selected interface.
    """
    from sniffer.core.interfaces import InterfaceManager

    console.print()
    console.print(
        Panel(
            "[bold bright_white]Select a Network Interface[/bold bright_white]\n"
            "[dim]Choose the interface you want to capture packets on.[/dim]",
            border_style="bright_blue",
        )
    )

    manager = InterfaceManager()
    interfaces = manager.list_interfaces(include_down=False)

    if not interfaces:
        console.print("[bold red]No active network interfaces found![/bold red]")
        console.print(
            "[dim]Diagnostic: Scapy could not detect interfaces. This is usually caused by:\n"
            "  1. Missing Npcap/WinPcap on Windows.\n"
            "  2. Missing Administrator/root privileges.\n"
            "  3. Incompatible or disabled network drivers.\n"
            "You can still try manually entering the exact name of your interface below.[/dim]\n"
        )
    else:
        # Display interfaces
        for i, iface in enumerate(interfaces, 1):
            icon = "📡" if not iface.is_loopback else "🔁"
            status = "[green]UP[/green]" if iface.is_up else "[red]DOWN[/red]"
            console.print(
                f"  [{i}] {icon} [bold cyan]{iface.name}[/bold cyan]"
                f"  {iface.ip_address}  {status}"
                f"  [dim]{iface.description}[/dim]"
            )
        console.print()

    # Get user selection
    from rich.prompt import Prompt

    while True:
        try:
            choice = Prompt.ask(
                "[bold]Enter interface number or exact name[/bold]",
                default="1" if interfaces else "",
                console=console,
            ).strip()

            if not choice:
                continue

            # If the user typed a number and we have interfaces
            if choice.isdigit() and interfaces:
                idx = int(choice)
                if 1 <= idx <= len(interfaces):
                    selected = interfaces[idx - 1]
                    console.print(
                        f"\n[green]✓[/green] Selected: [bold cyan]{selected.name}[/bold cyan]"
                        f" ({selected.ip_address})\n"
                    )
                    return selected.name
                else:
                    console.print(
                        f"[red]Please enter a number between 1 and {len(interfaces)}[/red]"
                    )
            else:
                # User typed a string (manual override) or digit with empty interfaces
                console.print(
                    f"\n[green]✓[/green] Selected manual override: [bold cyan]{choice}[/bold cyan]\n"
                )
                return choice

        except KeyboardInterrupt:
            console.print("\n[yellow]Selection cancelled.[/yellow]")
            sys.exit(0)


def interactive_filter_setup() -> str:
    """Interactively configure a BPF filter.

    Offers common presets and a custom filter option.

    Returns:
        A BPF filter string (empty string for no filter).
    """
    console.print(
        Panel(
            "[bold bright_white]Configure Packet Filter[/bold bright_white]\n"
            "[dim]Filter which packets to capture. Leave empty to capture everything.[/dim]",
            border_style="bright_blue",
        )
    )

    # Preset options
    presets = [
        ("All traffic (no filter)", ""),
        ("TCP only", "tcp"),
        ("UDP only", "udp"),
        ("HTTP (port 80)", "tcp port 80"),
        ("HTTPS (port 443)", "tcp port 443"),
        ("DNS (port 53)", "udp port 53"),
        ("ICMP (ping)", "icmp"),
        ("Custom filter...", None),
    ]

    for i, (label, _) in enumerate(presets, 1):
        console.print(f"  [{i}] {label}")

    console.print()

    while True:
        try:
            choice = IntPrompt.ask(
                "[bold]Select filter preset[/bold]",
                default=1,
                console=console,
            )
            if 1 <= choice <= len(presets):
                label, bpf = presets[choice - 1]
                if bpf is not None:
                    # Selected a preset
                    display_filter = bpf or "(none — capturing all traffic)"
                    console.print(
                        f"\n[green]✓[/green] Filter: [bold]{display_filter}[/bold]\n"
                    )
                    return bpf
                else:
                    # Custom filter
                    custom = Prompt.ask(
                        '[bold]Enter BPF filter[/bold] (e.g., "tcp port 80 and host 192.168.1.1")',
                        console=console,
                    )
                    console.print(f"\n[green]✓[/green] Filter: [bold]{custom}[/bold]\n")
                    return custom.strip()
            else:
                console.print(
                    f"[red]Please enter a number between 1 and {len(presets)}[/red]"
                )
        except (ValueError, KeyboardInterrupt):
            console.print("\n[yellow]Filter setup cancelled. Using no filter.[/yellow]")
            return ""


def interactive_export_prompt(
    parsed_packets: list[dict[str, Any]],
    raw_packets: list[Any],
) -> None:
    """Prompt the user to export captured data after capture stops.

    Offers CSV, JSON, and PCAP export options.

    Args:
        parsed_packets: Parsed packet dictionaries.
        raw_packets: Raw Scapy packet objects.
    """
    if not parsed_packets:
        console.print("[yellow]No packets captured — nothing to export.[/yellow]")
        return

    console.print()
    if not Confirm.ask(
        f"[bold]Export {len(parsed_packets)} captured packets?[/bold]",
        default=True,
        console=console,
    ):
        console.print("[dim]Export skipped.[/dim]")
        return

    # Export format selection
    formats = [
        ("CSV  (spreadsheet-friendly)", "csv"),
        ("JSON (preserves full structure)", "json"),
        ("PCAP (open in Wireshark)", "pcap"),
        ("All formats", "all"),
    ]

    console.print("\n[bold]Select export format:[/bold]")
    for i, (label, _) in enumerate(formats, 1):
        console.print(f"  [{i}] {label}")

    console.print()

    try:
        choice = IntPrompt.ask("[bold]Format[/bold]", default=1, console=console)
        if choice < 1 or choice > len(formats):
            choice = 1
    except (ValueError, KeyboardInterrupt):
        console.print("[dim]Export cancelled.[/dim]")
        return

    _, fmt = formats[choice - 1]
    _execute_export(fmt, parsed_packets, raw_packets)


def _execute_export(
    fmt: str,
    parsed_packets: list[dict[str, Any]],
    raw_packets: list[Any],
) -> None:
    """Execute the selected export format(s).

    Args:
        fmt: Export format key ("csv", "json", "pcap", or "all").
        parsed_packets: Parsed packet dictionaries.
        raw_packets: Raw Scapy packet objects.
    """
    from sniffer.export.csv_export import export_to_csv
    from sniffer.export.json_export import export_to_json
    from sniffer.export.pcap_export import export_to_pcap

    export_funcs = {
        "csv": lambda: export_to_csv(parsed_packets),
        "json": lambda: export_to_json(parsed_packets),
        "pcap": lambda: export_to_pcap(raw_packets),
    }

    formats_to_run = list(export_funcs.keys()) if fmt == "all" else [fmt]

    for export_fmt in formats_to_run:
        try:
            path = export_funcs[export_fmt]()
            console.print(
                f"  [green]✓[/green] {export_fmt.upper()} saved to: [bold]{path}[/bold]"
            )
        except Exception as exc:
            console.print(f"  [red]✗[/red] {export_fmt.upper()} export failed: {exc}")

    console.print()
