"""
PCAP Export Module
===================

Exports captured packets to PCAP (Packet Capture) format using
Scapy's ``wrpcap()`` function. PCAP files can be opened in
Wireshark for advanced analysis.

"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sniffer.utils.exceptions import ExportError
from sniffer.utils.logger import get_logger

logger = get_logger(__name__)


def export_to_pcap(
    raw_packets: list[Any],
    output_path: Path | str | None = None,
) -> Path:
    """Export raw Scapy packets to a PCAP file.

    Uses Scapy's ``wrpcap()`` to write packets in standard PCAP format
    that can be opened by Wireshark, tcpdump, and other analysis tools.

    Args:
        raw_packets: A list of raw Scapy packet objects.
        output_path: The output file path. If None, auto-generates
            a timestamped filename in ``./output/``.

    Returns:
        The ``Path`` to the created PCAP file.

    Raises:
        ExportError: If no packets to export or file write fails.

    Example:
        >>> # After capture:
        >>> raw = capture.get_raw_packets()
        >>> path = export_to_pcap(raw)
        >>> print(f"Open in Wireshark: {path}")
    """
    if not raw_packets:
        raise ExportError("No packets to export", details="Capture some packets first.")

    output = _resolve_output_path(output_path)

    try:
        from scapy.utils import wrpcap

        wrpcap(str(output), raw_packets)

        logger.info(
            "Exported %d packets to PCAP: %s (%.1f KB)",
            len(raw_packets),
            output,
            output.stat().st_size / 1024,
        )
        return output

    except ImportError as exc:
        raise ExportError(
            "Scapy is not installed — cannot write PCAP",
            details="Install with: pip install scapy",
        ) from exc
    except OSError as exc:
        raise ExportError(
            f"Failed to write PCAP file: {output}",
            details=str(exc),
        ) from exc


def _resolve_output_path(output_path: Path | str | None) -> Path:
    """Resolve and create the output file path.

    Args:
        output_path: User-specified path, or None for auto-generation.

    Returns:
        The resolved output ``Path``.
    """
    if output_path:
        path = Path(output_path)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("output")
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"capture_{timestamp}.pcap"

    path.parent.mkdir(parents=True, exist_ok=True)
    return path
