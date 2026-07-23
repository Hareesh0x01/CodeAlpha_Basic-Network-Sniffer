"""
Real-Time Terminal Dashboard
==============================

Displays captured packets in a live-updating terminal interface using
the ``rich`` library's Live display feature. Includes a header with
capture statistics and a scrolling packet stream.

"""

from __future__ import annotations

import threading
from collections import deque
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sniffer.core.capture import CaptureStats
from sniffer.display.colors import (
    get_highest_protocol,
    get_protocol_icon,
    get_protocol_style,
)
from sniffer.display.formatter import _extract_endpoints
from sniffer.utils.logger import get_logger

logger = get_logger(__name__)

# Maximum number of packets to display in the terminal
MAX_DISPLAY_PACKETS = 50


class LiveView:
    """Real-time terminal dashboard for packet capture.

    Displays a statistics header and a scrolling table of captured
    packets. Uses Rich's Live display for flicker-free updates.

    Example:
        >>> from sniffer.display.live_view import LiveView
        >>> view = LiveView()
        >>> view.start()
        >>> view.add_packet(parsed_packet_data)
        >>> # ... more packets ...
        >>> view.stop()
    """

    def __init__(self, interface_name: str = "", bpf_filter: str = "") -> None:
        """Initialize the live view.

        Args:
            interface_name: The interface being captured on (for display).
            bpf_filter: The active BPF filter (for display).
        """
        self._interface = interface_name
        self._bpf_filter = bpf_filter or "(none — capturing all traffic)"
        self._console = Console()
        self._packets: deque[dict[str, Any]] = deque(maxlen=MAX_DISPLAY_PACKETS)
        self._lock = threading.Lock()
        self._live: Live | None = None
        self._stats = CaptureStats()

        logger.debug("LiveView initialized for interface '%s'", interface_name)

    def update_stats(self, stats: CaptureStats) -> None:
        """Update the capture statistics displayed in the header.

        Args:
            stats: The current ``CaptureStats`` from the capture engine.
        """
        self._stats = stats

    def add_packet(self, packet_data: dict[str, Any]) -> None:
        """Add a parsed packet to the display buffer.

        Thread-safe — called from the capture thread.

        Args:
            packet_data: A parsed packet dictionary from ``parse_packet()``.
        """
        with self._lock:
            self._packets.append(packet_data)

        # Refresh the live display if running
        if self._live:
            try:
                self._live.update(self._build_layout())
            except Exception:
                pass  # Display errors are non-fatal

    def start(self) -> Live:
        """Start the live terminal display.

        Returns:
            The Rich ``Live`` context manager for use in a ``with`` block.
        """
        self._live = Live(
            self._build_layout(),
            console=self._console,
            refresh_per_second=4,
            screen=False,
        )
        logger.info("Live display started")
        return self._live

    def stop(self) -> None:
        """Stop the live terminal display."""
        if self._live:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None
        logger.info("Live display stopped")

    def _build_layout(self) -> Layout:
        """Build the complete terminal layout with stats and packet table.

        Returns:
            A Rich ``Layout`` object ready for rendering.
        """
        layout = Layout()
        layout.split_column(
            Layout(self._build_stats_panel(), name="stats", size=5),
            Layout(self._build_packet_table(), name="packets"),
        )
        return layout

    def _build_stats_panel(self) -> Panel:
        """Build the statistics header panel.

        Shows: packet count, bytes captured, duration, average and
        instantaneous capture rate, protocol distribution, interface
        name, and active BPF filter.

        Returns:
            A Rich ``Panel`` with formatted statistics.
        """
        stats = self._stats
        duration = stats.duration
        avg_rate = stats.packets_per_second
        inst_rate = stats.instantaneous_rate
        bps = stats.bytes_per_second

        # Format bytes in human-readable form
        bytes_str = self._format_bytes(stats.bytes_captured)
        bps_str = self._format_bytes(int(bps)) + "/s"

        # Format duration
        minutes, seconds = divmod(int(duration), 60)
        hours, minutes = divmod(minutes, 60)
        dur_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        # Line 1: Core metrics
        line1 = Text()
        line1.append("📦 Packets: ", style="bold")
        line1.append(f"{stats.packets_captured:,}  ", style="bold cyan")
        line1.append("📊 Data: ", style="bold")
        line1.append(f"{bytes_str} ({bps_str})  ", style="bold green")
        line1.append("⏱️  Duration: ", style="bold")
        line1.append(f"{dur_str}  ", style="bold yellow")
        line1.append("⚡ Rate: ", style="bold")
        line1.append(f"{inst_rate:.1f} pkt/s", style="bold magenta")
        line1.append(f" (avg {avg_rate:.1f})  ", style="dim")

        if stats.packets_dropped > 0:
            line1.append("⚠️  Dropped: ", style="bold red")
            line1.append(f"{stats.packets_dropped}", style="bold red")

        # Line 2: Protocol distribution (compact bar)
        line2 = Text()
        proto_dist = stats.get_protocol_distribution()
        if proto_dist:
            line2.append("📋 Protocols: ", style="bold")
            total = max(stats.packets_captured, 1)
            for proto, count, _bytes in proto_dist[:6]:  # Top 6 protocols
                pct = (count / total) * 100
                style = get_protocol_style(proto)
                line2.append(f"{proto}", style=style)
                line2.append(f":{count}({pct:.0f}%) ", style="dim")

        from rich.console import Group

        content = Group(line1, line2) if proto_dist else line1

        return Panel(
            content,
            title=f"[bold]🔍 Capturing on: {self._interface}[/bold]",
            subtitle=f"[dim]Filter: {self._bpf_filter}[/dim]",
            border_style="bright_blue",
        )

    def _build_packet_table(self) -> Table:
        """Build the scrolling packet table.

        Shows the most recent packets with columns for: number,
        timestamp, source, destination, protocol, info, and size.

        Returns:
            A Rich ``Table`` with the recent packet rows.
        """
        table = Table(
            show_header=True,
            header_style="bold bright_white",
            border_style="dim",
            expand=True,
            pad_edge=True,
        )

        # Define columns
        table.add_column("#", style="dim", width=6, justify="right")
        table.add_column("Time", style="dim", width=14)
        table.add_column("Source", width=16)
        table.add_column("SPort", width=6, justify="right")
        table.add_column("Destination", width=16)
        table.add_column("DPort", width=6, justify="right")
        table.add_column("Protocol", width=10, justify="center")
        table.add_column("Info", ratio=2)
        table.add_column("Size", width=8, justify="right")

        # Add packet rows
        with self._lock:
            for pkt in self._packets:
                self._add_packet_row(table, pkt)

        return table

    @staticmethod
    def _add_packet_row(table: Table, packet_data: dict[str, Any]) -> None:
        """Add a single packet as a row to the table.

        Args:
            table: The Rich ``Table`` to add the row to.
            packet_data: A parsed packet dictionary.
        """
        from datetime import datetime

        num = str(packet_data.get("packet_number", ""))
        timestamp = packet_data.get("timestamp", 0)
        time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]
        size = str(packet_data.get("size", 0))
        layers = packet_data.get("layers", [])

        top_protocol = get_highest_protocol(layers)
        style = get_protocol_style(top_protocol)
        icon = get_protocol_icon(top_protocol)

        src, dst, info = _extract_endpoints(packet_data, top_protocol)
        sport = str(packet_data.get("sport", "N/A"))
        dport = str(packet_data.get("dport", "N/A"))

        table.add_row(
            num,
            time_str,
            Text(src, style=style),
            sport,
            Text(dst, style=style),
            dport,
            Text(f"{icon} {top_protocol}", style=style),
            Text(info, style="dim" if not info else ""),
            size,
        )

    @staticmethod
    def _format_bytes(num_bytes: int) -> str:
        """Format a byte count in human-readable form (KB, MB, GB).

        Args:
            num_bytes: The byte count.

        Returns:
            A formatted string like "1.5 MB" or "340 bytes".
        """
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024:.1f} KB"
        elif num_bytes < 1024 * 1024 * 1024:
            return f"{num_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


def print_capture_banner(
    console: Console,
    interface: str,
    bpf_filter: str,
) -> None:
    """Print a startup banner before capture begins.

    Displays the interface, filter, and usage instructions.

    Args:
        console: A Rich ``Console`` instance.
        interface: The interface name being captured on.
        bpf_filter: The active BPF filter expression.
    """
    console.print()
    console.print(
        Panel(
            "[bold bright_white]🔍 Basic Network Sniffer[/bold bright_white]\n"
            "[dim]Educational Packet Capture Tool[/dim]\n\n"
            f"[bold]Interface:[/bold]  {interface}\n"
            f"[bold]Filter:[/bold]     {bpf_filter or '(none — capturing all traffic)'}\n\n"
            "[dim italic]Press Ctrl+C to stop capture...[/dim italic]",
            border_style="bright_blue",
            title="[bold]Starting Capture[/bold]",
        )
    )
    console.print()
