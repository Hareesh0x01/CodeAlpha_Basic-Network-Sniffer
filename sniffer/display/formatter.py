"""
Packet Data Formatter
======================

Converts parsed packet dictionaries into formatted strings for
terminal display. Supports multiple output modes: one-line summary,
detailed table, and raw JSON.

"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sniffer.display.colors import (
    get_highest_protocol,
    get_protocol_icon,
    get_protocol_style,
)


def format_summary_line(packet_data: dict[str, Any]) -> str:
    """Format a packet as a single summary line (like Wireshark's packet list).

    Produces a compact, color-coded line suitable for scrolling output:
    ``#1  12:34:56  192.168.1.1 → 8.8.8.8  TCP  80→443  [SYN]  74 bytes``

    Args:
        packet_data: A parsed packet dictionary from ``parse_packet()``.

    Returns:
        A Rich-markup formatted string for terminal display.
    """
    # Basic fields
    num = packet_data.get("packet_number", 0)
    size = packet_data.get("size", 0)
    layers = packet_data.get("layers", [])
    timestamp = packet_data.get("timestamp", 0)

    # Format timestamp as HH:MM:SS.mmm
    time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]

    # Determine the highest protocol for color coding
    top_protocol = get_highest_protocol(layers)
    style = get_protocol_style(top_protocol)
    icon = get_protocol_icon(top_protocol)

    # Extract source/destination info based on available layers
    src, dst, info = _extract_endpoints(packet_data, top_protocol)

    # Build the summary line
    num_str = f"[dim]#{num:<5}[/dim]"
    time_part = f"[dim]{time_str}[/dim]"
    endpoints = f"[{style}]{src} → {dst}[/{style}]"
    proto_part = f"[{style}]{icon} {top_protocol:<6}[/{style}]"
    info_part = f"[dim]{info}[/dim]" if info else ""
    size_part = f"[dim]{size} bytes[/dim]"

    parts = [num_str, time_part, endpoints, proto_part]
    if info_part:
        parts.append(info_part)
    parts.append(size_part)

    return "  ".join(parts)


def format_detailed(packet_data: dict[str, Any]) -> str:
    """Format a packet with full layer-by-layer details.

    Produces a multi-line output showing all parsed fields for each
    protocol layer, similar to Wireshark's packet detail pane.

    Args:
        packet_data: A parsed packet dictionary.

    Returns:
        A multi-line Rich-markup formatted string.
    """
    lines: list[str] = []

    # Header
    num = packet_data.get("packet_number", 0)
    size = packet_data.get("size", 0)
    timestamp = packet_data.get("timestamp", 0)
    time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    lines.append(f"[bold]{'═' * 60}[/bold]")
    lines.append(f"[bold]Packet #{num}[/bold]  |  {time_str}  |  {size} bytes")
    lines.append(f"[dim]Layers: {' → '.join(packet_data.get('layers', []))}[/dim]")

    # Layer details
    layer_order = ["ethernet", "ip", "arp", "tcp", "udp", "icmp", "dns", "http"]
    for layer_key in layer_order:
        layer_data = packet_data.get(layer_key)
        if layer_data is None:
            continue

        style = get_protocol_style(layer_key.upper() if layer_key != "ip" else "IP")
        lines.append(f"\n[{style}]── {layer_key.upper()} ──[/{style}]")

        for key, value in layer_data.items():
            # Skip internal/list fields in the summary
            if isinstance(value, (list, dict)):
                if isinstance(value, list) and value:
                    lines.append(f"  {key}: {len(value)} items")
                    for item in value[:5]:  # Show first 5 items
                        if isinstance(item, dict):
                            item_str = ", ".join(f"{k}={v}" for k, v in item.items())
                            lines.append(f"    → {item_str}")
                        else:
                            lines.append(f"    → {item}")
                continue
            lines.append(f"  {key}: {value}")

    lines.append(f"[bold]{'═' * 60}[/bold]")
    return "\n".join(lines)


def format_json(packet_data: dict[str, Any]) -> str:
    """Format a packet as pretty-printed JSON.

    Useful for debugging and programmatic processing.

    Args:
        packet_data: A parsed packet dictionary.

    Returns:
        A JSON-formatted string.
    """
    import json

    return json.dumps(packet_data, indent=2, default=str)


def _extract_endpoints(
    packet_data: dict[str, Any],
    top_protocol: str,
) -> tuple[str, str, str]:
    """Extract source, destination, and info strings from packet data.

    The "best" source/destination depends on the highest protocol:
    - For IP/TCP/UDP: use IP addresses + ports.
    - For ARP: use sender/target IPs.
    - For DNS: use query name.

    Args:
        packet_data: A parsed packet dictionary.
        top_protocol: The highest-level protocol in the packet.

    Returns:
        A tuple of (source, destination, info).
    """
    src = "?"
    dst = "?"
    info = ""

    # IP addresses (base for most protocols)
    ip_data = packet_data.get("ip")
    if ip_data:
        src = ip_data.get("src_ip", "?")
        dst = ip_data.get("dst_ip", "?")

    # TCP specifics
    tcp_data = packet_data.get("tcp")
    if tcp_data:
        tcp_data.get("src_port", "?")
        tcp_data.get("dst_port", "?")
        flags = tcp_data.get("flags", "")
        service = tcp_data.get("dst_service", "") or tcp_data.get("src_service", "")
        # Ports are handled in dedicated columns now
        info_parts = []
        if flags:
            info_parts.append(f"[{flags}]")
        if service:
            info_parts.append(service)
        info = " ".join(info_parts)

    # UDP specifics
    elif packet_data.get("udp"):
        udp_data = packet_data["udp"]
        udp_data.get("src_port", "?")
        udp_data.get("dst_port", "?")
        service = udp_data.get("dst_service", "") or udp_data.get("src_service", "")
        # Ports are handled in dedicated columns now
        if service:
            info = service

    # DNS specifics (override info)
    dns_data = packet_data.get("dns")
    if dns_data:
        query = dns_data.get("query_name", "")
        qtype = dns_data.get("query_type_name", "")
        if dns_data.get("is_response"):
            answer_count = dns_data.get("answer_count", 0)
            info = f"Response: {query} ({qtype}) [{answer_count} answers]"
        else:
            info = f"Query: {query} ({qtype})"

    # HTTP specifics (override info)
    http_data = packet_data.get("http")
    if http_data:
        if http_data.get("is_request"):
            method = http_data.get("method", "?")
            url = http_data.get("url", "/")
            host = http_data.get("host", "")
            info = f"{method} {host}{url}"
        else:
            status = http_data.get("status_code", "?")
            text = http_data.get("status_text", "")
            info = f"{status} {text}"

    # ARP specifics
    arp_data = packet_data.get("arp")
    if arp_data:
        src = arp_data.get("sender_ip", "?")
        dst = arp_data.get("target_ip", "?")
        info = arp_data.get("summary", "")

    # ICMP specifics
    icmp_data = packet_data.get("icmp")
    if icmp_data and top_protocol == "ICMP":
        info = icmp_data.get("type_name", "")
        code_name = icmp_data.get("code_name", "")
        if code_name:
            info = f"{info} ({code_name})"

    return src, dst, info
