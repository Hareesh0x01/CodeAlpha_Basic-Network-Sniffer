"""
ICMP Message Parser
====================

Parses ICMP (Internet Control Message Protocol) messages, which are
used for network diagnostics and error reporting.

"""

from __future__ import annotations

from typing import Any

from sniffer.parsers.base import BaseParser

# ICMP type → name mapping (with common codes)
ICMP_TYPES: dict[int, str] = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    30: "Traceroute",
}

# Destination Unreachable codes (Type 3)
DEST_UNREACHABLE_CODES: dict[int, str] = {
    0: "Network Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
    6: "Destination Network Unknown",
    7: "Destination Host Unknown",
    13: "Communication Administratively Prohibited",
}

# Time Exceeded codes (Type 11)
TIME_EXCEEDED_CODES: dict[int, str] = {
    0: "TTL Exceeded in Transit",
    1: "Fragment Reassembly Time Exceeded",
}


class ICMPParser(BaseParser):
    """Parses ICMP (Layer 3) control messages.

    Extracts:
        - ``type``: ICMP message type number.
        - ``code``: ICMP message code number.
        - ``type_name``: Human-readable type name.
        - ``code_name``: Human-readable code name (type-specific).
        - ``identifier``: Echo identifier (echo req/reply only).
        - ``sequence``: Echo sequence number (echo req/reply only).
        - ``checksum``: ICMP checksum value.
    """

    @property
    def layer_name(self) -> str:
        return "ICMP"

    def can_parse(self, packet: Any) -> bool:
        """Check if the packet has an ICMP layer."""
        from scapy.layers.inet import ICMP

        return packet.haslayer(ICMP)

    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract ICMP message fields.

        Args:
            packet: A Scapy packet containing an ICMP layer.

        Returns:
            Dictionary with ICMP fields.

        Example output (ping request)::

            {
                "type": 8,
                "code": 0,
                "type_name": "Echo Request",
                "code_name": "",
                "identifier": 12345,
                "sequence": 1,
                "checksum": 54321
            }
        """
        from scapy.layers.inet import ICMP

        icmp = packet[ICMP]
        icmp_type = icmp.type
        icmp_code = icmp.code

        result: dict[str, Any] = {
            "type": icmp_type,
            "code": icmp_code,
            "type_name": ICMP_TYPES.get(icmp_type, f"Unknown Type ({icmp_type})"),
            "code_name": self._get_code_name(icmp_type, icmp_code),
            "checksum": icmp.chksum,
        }

        # Echo Request/Reply have identifier and sequence fields
        if icmp_type in (0, 8):
            result["identifier"] = icmp.id
            result["sequence"] = icmp.seq

        return result

    @staticmethod
    def _get_code_name(icmp_type: int, code: int) -> str:
        """Get a human-readable name for an ICMP code.

        Code meanings are context-dependent — they vary by type.

        Args:
            icmp_type: The ICMP type number.
            code: The ICMP code number.

        Returns:
            A human-readable code name, or empty string if not applicable.
        """
        if icmp_type == 3:
            return DEST_UNREACHABLE_CODES.get(code, f"Code {code}")
        if icmp_type == 11:
            return TIME_EXCEEDED_CODES.get(code, f"Code {code}")
        if code == 0:
            return ""  # Code 0 is "no sub-code" for most types
        return f"Code {code}"
