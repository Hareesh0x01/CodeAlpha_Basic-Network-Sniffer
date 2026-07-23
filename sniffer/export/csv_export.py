"""
CSV Export Module
==================

Exports captured packets to CSV (Comma-Separated Values) format.
CSV is universally supported by spreadsheet applications (Excel,
Google Sheets) and data analysis tools (pandas, R).

"""

from __future__ import annotations

import csv
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from sniffer.utils.exceptions import ExportError
from sniffer.utils.logger import get_logger

logger = get_logger(__name__)


def export_to_csv(
    packets: list[dict[str, Any]],
    output_path: Path | str | None = None,
) -> Path:
    """Export parsed packets to a CSV file.

    Flattens nested packet data into columns. Nested dicts are
    prefixed with their layer name (e.g., ``ip_src_ip``, ``tcp_dst_port``).

    Args:
        packets: A list of parsed packet dictionaries.
        output_path: The output file path. If None, auto-generates
            a timestamped filename in ``./output/``.

    Returns:
        The ``Path`` to the created CSV file.

    Raises:
        ExportError: If no packets to export or file write fails.

    Example:
        >>> packets = [{"packet_number": 1, "size": 64, "ip": {"src_ip": "1.2.3.4"}}]
        >>> path = export_to_csv(packets)
        >>> print(f"Saved to {path}")
    """
    if not packets:
        raise ExportError("No packets to export", details="Capture some packets first.")

    # Determine output path
    output = _resolve_output_path(output_path, extension=".csv")

    try:
        # Flatten all packets and determine the full set of columns
        flat_packets = [_flatten_packet(pkt) for pkt in packets]
        all_columns = _get_all_columns(flat_packets)

        # Write to a temp file, then rename (atomic write)
        temp_fd, temp_path = tempfile.mkstemp(
            suffix=".csv",
            dir=output.parent,
        )

        with open(temp_fd, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=all_columns,
                extrasaction="ignore",
                restval="",
            )
            writer.writeheader()
            writer.writerows(flat_packets)

        # Atomic rename
        temp_path_obj = Path(temp_path)
        temp_path_obj.replace(output)

        logger.info("Exported %d packets to CSV: %s", len(packets), output)
        return output

    except OSError as exc:
        raise ExportError(
            f"Failed to write CSV file: {output}",
            details=str(exc),
        ) from exc


def _flatten_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Flatten a nested packet dictionary into a single-level dict.

    Nested dictionaries are prefixed with their parent key:
    ``{"ip": {"src_ip": "1.2.3.4"}}`` → ``{"ip_src_ip": "1.2.3.4"}``

    Lists are serialized to semicolon-separated strings.

    Args:
        packet: A parsed packet dictionary (potentially nested).

    Returns:
        A flat dictionary with string keys and scalar values.
    """
    flat: dict[str, Any] = {}

    for key, value in packet.items():
        if isinstance(value, dict):
            # Prefix nested keys with the parent key
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, list):
                    flat[f"{key}_{sub_key}"] = "; ".join(
                        str(item) for item in sub_value
                    )
                else:
                    flat[f"{key}_{sub_key}"] = sub_value
        elif isinstance(value, list):
            flat[key] = "; ".join(str(item) for item in value)
        else:
            flat[key] = value

    return flat


def _get_all_columns(flat_packets: list[dict[str, Any]]) -> list[str]:
    """Collect all unique column names across all packets.

    Preserves a sensible ordering: common fields first, then
    layer-specific fields in alphabetical order.

    Args:
        flat_packets: A list of flattened packet dictionaries.

    Returns:
        An ordered list of column names.
    """
    # Priority columns that should appear first
    priority = ["packet_number", "timestamp", "size", "layers", "raw_summary"]

    all_keys: set[str] = set()
    for pkt in flat_packets:
        all_keys.update(pkt.keys())

    # Priority columns first, then remaining in sorted order
    ordered = [k for k in priority if k in all_keys]
    remaining = sorted(all_keys - set(ordered))
    return ordered + remaining


def _resolve_output_path(output_path: Path | str | None, extension: str) -> Path:
    """Resolve and create the output file path.

    If no path is provided, generates a timestamped filename in
    the ``./output/`` directory.

    Args:
        output_path: User-specified path, or None for auto-generation.
        extension: File extension (e.g., ".csv", ".json").

    Returns:
        The resolved output ``Path``.
    """
    if output_path:
        path = Path(output_path)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("output")
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"capture_{timestamp}{extension}"

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
