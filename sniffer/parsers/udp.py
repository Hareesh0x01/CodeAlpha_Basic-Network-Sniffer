"""
UDP Datagram Parser (Layer 4)
==============================

Parses UDP datagram headers to extract port numbers, length, and checksum.

"""

from __future__ import annotations

from typing import Any

from sniffer.parsers.base import BaseParser

# Well-known UDP ports → service names
UDP_SERVICES: dict[int, str] = {
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-Trap",
    443: "QUIC/HTTPS",
    500: "IKE",
    514: "Syslog",
    1194: "OpenVPN",
    1900: "SSDP/UPnP",
    4500: "IPsec NAT-T",
    5353: "mDNS",
    5355: "LLMNR",
}


class UDPParser(BaseParser):
    """Parses UDP (Layer 4) datagram headers.

    Extracts:
        - ``src_port``: Source port number.
        - ``dst_port``: Destination port number.
        - ``src_service``: Service name for source port (if known).
        - ``dst_service``: Service name for destination port (if known).
        - ``length``: Total datagram length (header + payload) in bytes.
        - ``checksum``: UDP checksum value.
        - ``payload_size``: Payload size in bytes (length - 8).
    """

    @property
    def layer_name(self) -> str:
        return "UDP"

    def can_parse(self, packet: Any) -> bool:
        """Check if the packet has a UDP layer."""
        from scapy.layers.inet import UDP

        return packet.haslayer(UDP)

    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract UDP datagram fields.

        Args:
            packet: A Scapy packet containing a UDP layer.

        Returns:
            Dictionary with UDP fields.

        Example output::

            {
                "src_port": 12345,
                "dst_port": 53,
                "src_service": "",
                "dst_service": "DNS",
                "length": 42,
                "checksum": 45678,
                "payload_size": 34
            }
        """
        from scapy.layers.inet import UDP

        udp = packet[UDP]
        return {
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "src_service": UDP_SERVICES.get(udp.sport, ""),
            "dst_service": UDP_SERVICES.get(udp.dport, ""),
            "length": udp.len,
            "checksum": udp.chksum,
            "payload_size": max(0, udp.len - 8),  # 8-byte header
        }
