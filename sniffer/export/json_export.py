"""
JSON Export Module
===================

Exports captured packets to JSON (JavaScript Object Notation) format.
JSON preserves the full nested structure of parsed packets, making it
ideal for programmatic analysis and data interchange.

"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from sniffer.utils.exceptions import ExportError
from sniffer.utils.logger import get_logger

logger = get_logger(__name__)


def export_to_json(
    packets: list[dict[str, Any]],
    output_path: Path | str | None = None,
    ndjson: bool = False,
    indent: int = 2,
) -> Path:
    """Export parsed packets to a JSON file.

    Args:
        packets: A list of parsed packet dictionaries.
        output_path: The output file path. If None, auto-generates
            a timestamped filename in ``./output/``.
        ndjson: If True, use NDJSON format (one JSON object per line).
            Default is False (standard JSON array).
        indent: JSON indentation level (ignored for NDJSON).

    Returns:
        The ``Path`` to the created JSON file.

    Raises:
        ExportError: If no packets to export or file write fails.

    Example:
        >>> packets = [{"packet_number": 1, "size": 64, "layers": ["IP", "TCP"]}]
        >>> path = export_to_json(packets)
        >>> print(f"Saved to {path}")
    """
    if not packets:
        raise ExportError("No packets to export", details="Capture some packets first.")

    # Determine file extension
    extension = ".ndjson" if ndjson else ".json"
    output = _resolve_output_path(output_path, extension)

    try:
        # Write to a temp file, then rename (atomic write)
        temp_fd, temp_path = tempfile.mkstemp(
            suffix=extension,
            dir=output.parent,
        )

        with open(temp_fd, "w", encoding="utf-8") as jsonfile:
            if ndjson:
                # NDJSON: one JSON object per line
                for packet in packets:
                    line = json.dumps(packet, default=str, ensure_ascii=False)
                    jsonfile.write(line + "\n")
            else:
                # Standard JSON: array of objects
                json.dump(
                    _build_export_document(packets),
                    jsonfile,
                    indent=indent,
                    default=str,
                    ensure_ascii=False,
                )

        # Atomic rename
        temp_path_obj = Path(temp_path)
        temp_path_obj.replace(output)

        format_name = "NDJSON" if ndjson else "JSON"
        logger.info("Exported %d packets to %s: %s", len(packets), format_name, output)
        return output

    except OSError as exc:
        raise ExportError(
            f"Failed to write JSON file: {output}",
            details=str(exc),
        ) from exc


def _build_export_document(packets: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a complete JSON export document with metadata.

    Wraps the packet array in a document with export metadata:
    timestamp, packet count, and version information.

    Args:
        packets: A list of parsed packet dictionaries.

    Returns:
        A dictionary representing the full JSON document.
    """
    return {
        "metadata": {
            "tool": "Basic Network Sniffer",
            "version": "1.0.0",
            "export_timestamp": datetime.now().isoformat(),
            "packet_count": len(packets),
        },
        "packets": packets,
    }


def _resolve_output_path(output_path: Path | str | None, extension: str) -> Path:
    """Resolve and create the output file path.

    Args:
        output_path: User-specified path, or None for auto-generation.
        extension: File extension.

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

    path.parent.mkdir(parents=True, exist_ok=True)
    return path
