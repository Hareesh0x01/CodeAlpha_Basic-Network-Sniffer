"""
Protocol Parser Registry
=========================

Registers all protocol parsers and provides the ``parse_packet()``
function that runs a raw Scapy packet through the entire parser pipeline.

"""

from __future__ import annotations

import time
from typing import Any

from sniffer.parsers.arp import ARPParser
from sniffer.parsers.base import BaseParser
from sniffer.parsers.dns import DNSParser
from sniffer.parsers.ethernet import EthernetParser
from sniffer.parsers.http import HTTPParser
from sniffer.parsers.icmp import ICMPParser
from sniffer.parsers.ip import IPParser
from sniffer.parsers.tcp import TCPParser
from sniffer.parsers.udp import UDPParser
from sniffer.utils.logger import get_logger

logger = get_logger(__name__)

# ─── Parser Registry ────────────────────────────────────────────────────────
# Ordered from Layer 2 → Layer 7. Each parser runs independently.
# To add a new parser: create the class, import it here, add to this list.
PARSERS: list[BaseParser] = [
    EthernetParser(),  # Layer 2
    IPParser(),  # Layer 3
    ARPParser(),  # Layer 2/3
    TCPParser(),  # Layer 4
    UDPParser(),  # Layer 4
    ICMPParser(),  # Layer 3 (control)
    DNSParser(),  # Layer 7
    HTTPParser(),  # Layer 7
]


def parse_packet(raw_packet: Any, packet_number: int = 0) -> dict[str, Any]:
    """Parse a raw Scapy packet through all registered parsers.

    Runs the packet through each parser in the registry. Each parser
    that can handle the packet adds its data under a key matching
    its ``layer_name`` (lowercased).

    Args:
        raw_packet: A raw Scapy packet object.
        packet_number: Sequential packet number for identification.

    Returns:
        A dictionary with the following structure::

            {
                "timestamp": 1234567890.123,
                "packet_number": 1,
                "size": 74,
                "layers": ["Ethernet", "IP", "TCP"],
                "ethernet": { ... },
                "ip": { ... },
                "tcp": { ... },
                "raw_summary": "Ether / IP / TCP ..."
            }

    Example:
        >>> from scapy.all import IP, TCP, Ether
        >>> pkt = Ether() / IP(dst="8.8.8.8") / TCP(dport=80)
        >>> result = parse_packet(pkt, packet_number=1)
        >>> print(result["layers"])
        ['Ethernet', 'IP', 'TCP']
    """
    parsed: dict[str, Any] = {
        "timestamp": time.time(),
        "packet_number": packet_number,
        "size": len(raw_packet),
        "layers": [],
        "raw_summary": (
            raw_packet.summary() if hasattr(raw_packet, "summary") else str(raw_packet)
        ),
    }

    # Run through each parser in the registry
    for parser in PARSERS:
        try:
            result = parser.parse_safe(raw_packet)
            if result is not None:
                layer_key = parser.layer_name.lower()
                parsed[layer_key] = result
                parsed["layers"].append(parser.layer_name)
        except Exception as exc:
            # This should never happen (parse_safe catches errors),
            # but defense-in-depth is important.
            logger.error(
                "Unexpected error in parser '%s': %s",
                parser.layer_name,
                exc,
            )

    # Elevate ports to top-level for UI and exporters
    sport = "N/A"
    dport = "N/A"

    if "tcp" in parsed:
        sport = parsed["tcp"].get("src_port", "N/A")
        dport = parsed["tcp"].get("dst_port", "N/A")
    elif "udp" in parsed:
        sport = parsed["udp"].get("src_port", "N/A")
        dport = parsed["udp"].get("dst_port", "N/A")

    parsed["sport"] = sport
    parsed["dport"] = dport

    return parsed


def get_parser_names() -> list[str]:
    """Return the names of all registered parsers.

    Returns:
        A list of parser layer names (e.g., ["Ethernet", "IP", "TCP", ...]).
    """
    return [p.layer_name for p in PARSERS]
