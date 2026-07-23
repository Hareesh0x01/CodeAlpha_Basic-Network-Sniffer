"""
Application Entry Point
========================

This module is executed when the user runs ``python -m sniffer``.
It orchestrates the complete startup sequence:

1. Parse CLI arguments.
2. Load configuration (CLI > TOML config > env vars > defaults).
3. Configure logging.
4. Check privileges (admin/root).
5. Discover and select a network interface.
6. Configure BPF filters.
7. Start the capture engine.
8. Display packets in real-time with live dashboard.
9. Handle graceful shutdown (Ctrl+C, with double Ctrl+C force-quit).
10. Show post-capture statistics (protocol breakdown, top talkers).
11. Auto-save and/or offer interactive export.

"""

from __future__ import annotations

import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sniffer.utils.logger import get_logger

logger = get_logger(__name__)

# Rich console for startup messages
console = Console()


def main() -> int:
    """Main entry point for the Basic Network Sniffer.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    try:
        return _run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Goodbye! 👋[/yellow]")
        return 0
    except Exception as exc:
        console.print(f"\n[bold red]Fatal error:[/bold red] {exc}")
        logger.critical("Unhandled exception: %s", exc, exc_info=True)
        return 1


def _run() -> int:
    """Core application logic (separated from main for testability).

    Returns:
        Exit code (0 = success, 1 = error).
    """
    # ── Step 1: Parse CLI arguments ─────────────────────────────────────
    from sniffer.cli import (
        interactive_export_prompt,
        interactive_filter_setup,
        interactive_interface_selection,
        parse_arguments,
        show_interfaces_table,
    )

    args = parse_arguments()

    # ── Step 2: Load configuration (CLI > TOML > env > defaults) ────────
    from sniffer.config import SnifferConfig
    from sniffer.utils.logger import setup_logging

    config = SnifferConfig.from_env(
        interface=args.interface,
        bpf_filter=getattr(args, "filter", ""),
        packet_count=getattr(args, "count", 0),
        timeout=getattr(args, "timeout", 0),
        verbose=args.verbose,
        debug=args.debug,
        no_color=args.no_color,
    )

    # ── Step 3: Configure logging ───────────────────────────────────────
    setup_logging(console_level=config.get_console_log_level(), log_dir=config.log_dir)
    logger.info("Basic Network Sniffer v%s starting", "1.0.0")
    logger.debug("Configuration: %s", config)
    logger.info("Log file: %s", (config.log_dir / "sniffer.log").resolve())

    # ── Step 4: Handle 'list-interfaces' command ────────────────────────
    if args.command == "list-interfaces":
        show_interfaces_table()
        return 0

    # ── Step 5: Check privileges ────────────────────────────────────────
    from sniffer.utils.permissions import check_privileges

    try:
        check_privileges()
    except Exception as exc:
        console.print(f"\n[bold red]❌ {exc}[/bold red]")
        if hasattr(exc, "details") and exc.details:
            console.print(f"[dim]{exc.details}[/dim]")
        logger.critical("Privilege check failed: %s", exc)
        return 1

    # ── Step 6: Select network interface ────────────────────────────────
    interface = config.interface
    if not interface:
        # Interactive mode: let the user pick
        interface = interactive_interface_selection()

    # ── Step 7: Configure BPF filter ────────────────────────────────────
    bpf_filter = config.bpf_filter
    if not bpf_filter and not config.interface:
        # Interactive mode: let the user configure filters
        bpf_filter = interactive_filter_setup()

    # ── Step 8: Start capture engine ────────────────────────────────────
    from sniffer.core.capture import PacketCapture
    from sniffer.display.live_view import LiveView, print_capture_banner

    capture = PacketCapture(
        interface=interface,
        bpf_filter=bpf_filter,
        packet_count=config.packet_count,
        timeout=config.timeout,
    )

    # Create the live display
    live_view = LiveView(interface_name=interface, bpf_filter=bpf_filter)

    # Register callback to feed packets to the display
    def display_callback(_raw_pkt: object, parsed_data: dict) -> None:
        live_view.add_packet(parsed_data)
        live_view.update_stats(capture.stats)

    capture.add_callback(display_callback)

    # Print startup banner
    print_capture_banner(console, interface, bpf_filter)

    # Log capture start
    logger.info(
        "Starting capture: interface=%s, filter='%s', count=%d, timeout=%d",
        interface,
        bpf_filter or "(none)",
        config.packet_count,
        config.timeout,
    )

    # Start capturing
    capture.start()

    # ── Step 9: Run live display until Ctrl+C (with force-quit) ─────────
    _last_interrupt = [0.0]  # Mutable closure variable for double Ctrl+C detection

    try:
        live_display = live_view.start()
        with live_display:
            while capture.is_running:
                time.sleep(0.25)
                live_display.update(live_view._build_layout())
    except KeyboardInterrupt:
        _last_interrupt[0] = time.time()
        console.print(
            "\n[yellow]Stopping capture... (press Ctrl+C again to force quit)[/yellow]"
        )
    finally:
        stats = capture.stop()
        live_view.stop()

    # Log capture end
    logger.info(
        "Capture complete: %d packets, %d bytes, %.1fs duration, %.1f pkt/s avg",
        stats.packets_captured,
        stats.bytes_captured,
        stats.duration,
        stats.packets_per_second,
    )

    # ── Step 10: Print capture summary ──────────────────────────────────
    _print_capture_summary(stats, live_view)

    # Show detailed statistics if --stats flag or always in interactive mode
    show_stats = getattr(args, "stats", False) or not config.interface
    if show_stats and stats.packets_captured > 0:
        _print_protocol_stats(stats)
        _print_top_talkers(stats)

    # ── Step 11: Auto-save (if flags set) ───────────────────────────────
    parsed_packets = capture.get_packets()
    raw_packets = capture.get_raw_packets()

    auto_saved = _handle_auto_save(args, parsed_packets, raw_packets)

    # ── Step 12: CLI export flags ───────────────────────────────────────
    cli_export = auto_saved
    if getattr(args, "csv", False):
        cli_export = True
        from sniffer.export.csv_export import export_to_csv

        try:
            path = export_to_csv(parsed_packets, args.output)
            console.print(f"  [green]✓[/green] CSV saved to: [bold]{path}[/bold]")
        except Exception as exc:
            console.print(f"  [red]✗[/red] CSV export failed: {exc}")

    if getattr(args, "json", False):
        cli_export = True
        from sniffer.export.json_export import export_to_json

        try:
            path = export_to_json(parsed_packets, args.output)
            console.print(f"  [green]✓[/green] JSON saved to: [bold]{path}[/bold]")
        except Exception as exc:
            console.print(f"  [red]✗[/red] JSON export failed: {exc}")

    if getattr(args, "pcap", False):
        cli_export = True
        from sniffer.export.pcap_export import export_to_pcap

        try:
            path = export_to_pcap(raw_packets, args.output)
            console.print(f"  [green]✓[/green] PCAP saved to: [bold]{path}[/bold]")
        except Exception as exc:
            console.print(f"  [red]✗[/red] PCAP export failed: {exc}")

    # If no CLI/auto export, offer interactive export
    if not cli_export and parsed_packets:
        interactive_export_prompt(parsed_packets, raw_packets)

    console.print("[dim]Goodbye! 👋[/dim]\n")
    return 0


# ── Post-Capture Display Functions ──────────────────────────────────────────


def _print_capture_summary(stats: object, live_view: object) -> None:
    """Print a rich capture summary panel after capture stops.

    Shows total packets, bytes, duration, rate, and protocol overview
    in a professional panel.

    Args:
        stats: The ``CaptureStats`` from the capture engine.
        live_view: The ``LiveView`` instance (for _format_bytes helper).
    """
    from sniffer.display.live_view import LiveView

    console.print()

    # Build summary text
    summary = Text()
    summary.append("✓ ", style="bold green")
    summary.append("Capture Complete\n\n", style="bold bright_white")

    summary.append("  📦 Total Packets:   ", style="bold")
    summary.append(f"{stats.packets_captured:,}\n", style="bold cyan")

    summary.append("  📊 Total Data:      ", style="bold")
    summary.append(
        f"{LiveView._format_bytes(stats.bytes_captured)}\n", style="bold green"
    )

    summary.append("  ⏱️  Duration:        ", style="bold")
    minutes, seconds = divmod(int(stats.duration), 60)
    hours, minutes = divmod(minutes, 60)
    summary.append(f"{hours:02d}:{minutes:02d}:{seconds:02d}\n", style="bold yellow")

    summary.append("  ⚡ Average Rate:    ", style="bold")
    summary.append(
        f"{stats.packets_per_second:.1f} packets/sec\n", style="bold magenta"
    )

    summary.append("  📈 Data Rate:       ", style="bold")
    summary.append(
        f"{LiveView._format_bytes(int(stats.bytes_per_second))}/s\n",
        style="bold magenta",
    )

    if stats.packets_dropped > 0:
        summary.append(
            f"\n  ⚠️  Dropped: {stats.packets_dropped} packets", style="bold red"
        )

    console.print(
        Panel(summary, border_style="green", title="[bold]Capture Summary[/bold]")
    )


def _print_protocol_stats(stats: object) -> None:
    """Print a detailed protocol breakdown table.

    Shows each protocol's packet count, percentage, and total bytes.

    Args:
        stats: The ``CaptureStats`` with protocol distribution data.
    """
    from sniffer.display.colors import get_protocol_icon, get_protocol_style
    from sniffer.display.live_view import LiveView

    proto_dist = stats.get_protocol_distribution()
    if not proto_dist:
        return

    table = Table(
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_blue",
        title="[bold]Protocol Distribution[/bold]",
        title_style="bold",
    )
    table.add_column("Protocol", width=14)
    table.add_column("Packets", justify="right", width=10)
    table.add_column("Percentage", justify="center", width=12)
    table.add_column("Bytes", justify="right", width=12)
    table.add_column("Distribution", width=30)

    total = max(stats.packets_captured, 1)
    for proto, count, byte_count in proto_dist:
        pct = (count / total) * 100
        style = get_protocol_style(proto)
        icon = get_protocol_icon(proto)

        # Create a visual bar
        bar_width = int(pct / 100 * 25)
        bar = "█" * bar_width + "░" * (25 - bar_width)

        table.add_row(
            Text(f"{icon} {proto}", style=style),
            f"{count:,}",
            f"{pct:.1f}%",
            LiveView._format_bytes(byte_count),
            Text(bar, style=style),
        )

    console.print(table)
    console.print()


def _print_top_talkers(stats: object) -> None:
    """Print the top source and destination IP addresses.

    Args:
        stats: The ``CaptureStats`` with IP counter data.
    """
    talkers = stats.get_top_talkers(5)
    sources = talkers.get("sources", [])
    destinations = talkers.get("destinations", [])

    if not sources and not destinations:
        return

    table = Table(
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_blue",
        title="[bold]Top Talkers[/bold]",
        title_style="bold",
    )
    table.add_column("#", width=4, justify="right", style="dim")
    table.add_column("Source IP", width=20, style="cyan")
    table.add_column("Packets", width=10, justify="right")
    table.add_column("", width=4)  # Spacer
    table.add_column("Destination IP", width=20, style="green")
    table.add_column("Packets", width=10, justify="right")

    max_rows = max(len(sources), len(destinations))
    for i in range(min(max_rows, 5)):
        src_ip = sources[i][0] if i < len(sources) else ""
        src_count = str(sources[i][1]) if i < len(sources) else ""
        dst_ip = destinations[i][0] if i < len(destinations) else ""
        dst_count = str(destinations[i][1]) if i < len(destinations) else ""

        table.add_row(str(i + 1), src_ip, src_count, "│", dst_ip, dst_count)

    console.print(table)
    console.print()


def _handle_auto_save(
    args: object,
    parsed_packets: list,
    raw_packets: list,
) -> bool:
    """Handle auto-save flags (--auto-pcap, --auto-csv, --auto-json).

    Automatically exports capture data without user interaction.

    Args:
        args: The parsed CLI arguments namespace.
        parsed_packets: Parsed packet dictionaries.
        raw_packets: Raw Scapy packet objects.

    Returns:
        True if any auto-save was performed.
    """
    saved = False

    if not parsed_packets and not raw_packets:
        return False

    if getattr(args, "auto_pcap", False):
        saved = True
        from sniffer.export.pcap_export import export_to_pcap

        try:
            path = export_to_pcap(raw_packets)
            console.print(f"  [green]✓[/green] Auto-saved PCAP: [bold]{path}[/bold]")
            logger.info("Auto-saved PCAP to %s", path)
        except Exception as exc:
            console.print(f"  [red]✗[/red] Auto-save PCAP failed: {exc}")
            logger.error("Auto-save PCAP failed: %s", exc)

    if getattr(args, "auto_csv", False):
        saved = True
        from sniffer.export.csv_export import export_to_csv

        try:
            path = export_to_csv(parsed_packets)
            console.print(f"  [green]✓[/green] Auto-saved CSV: [bold]{path}[/bold]")
            logger.info("Auto-saved CSV to %s", path)
        except Exception as exc:
            console.print(f"  [red]✗[/red] Auto-save CSV failed: {exc}")
            logger.error("Auto-save CSV failed: %s", exc)

    if getattr(args, "auto_json", False):
        saved = True
        from sniffer.export.json_export import export_to_json

        try:
            path = export_to_json(parsed_packets)
            console.print(f"  [green]✓[/green] Auto-saved JSON: [bold]{path}[/bold]")
            logger.info("Auto-saved JSON to %s", path)
        except Exception as exc:
            console.print(f"  [red]✗[/red] Auto-save JSON failed: {exc}")
            logger.error("Auto-save JSON failed: %s", exc)

    return saved


# ── Entry Point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sys.exit(main())
