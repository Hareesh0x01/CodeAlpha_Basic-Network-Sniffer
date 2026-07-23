"""
IP Packet Parser (Layer 3)
===========================

Parses IPv4 and IPv6 headers to extract addressing, routing, and
protocol identification fields.

"""

from __future__ import annotations

from typing import Any

from sniffer.parsers.base import BaseParser

# IP protocol number → name mapping
IP_PROTOCOLS: dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-in-IPv4",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


class IPParser(BaseParser):
    """Parses IPv4 and IPv6 (Layer 3) packet headers.

    Extracts:
        - ``version``: IP version (4 or 6).
        - ``src_ip``: Source IP address.
        - ``dst_ip``: Destination IP address.
        - ``ttl``: Time To Live / Hop Limit.
        - ``protocol``: Layer 4 protocol number.
        - ``protocol_name``: Human-readable protocol name.
        - ``header_length``: IP header size in bytes.
        - ``total_length``: Total packet size in bytes.
        - ``flags``: IP flags (IPv4 only).
        - ``traffic_class``: Traffic class (IPv6 only).
    """

    @property
    def layer_name(self) -> str:
        return "IP"

    def can_parse(self, packet: Any) -> bool:
        """Check if the packet has an IP or IPv6 layer."""
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6

        return packet.haslayer(IP) or packet.haslayer(IPv6)

    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract IP header fields.

        Automatically detects IPv4 vs IPv6 and extracts the
        appropriate fields for each version.

        Args:
            packet: A Scapy packet with an IP or IPv6 layer.

        Returns:
            Dictionary with IP fields.

        Example output (IPv4)::

            {
                "version": 4,
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "ttl": 64,
                "protocol": 6,
                "protocol_name": "TCP",
                "header_length": 20,
                "total_length": 60,
                "flags": "DF"
            }
        """
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6

        if packet.haslayer(IP):
            return self._parse_ipv4(packet[IP])
        else:
            return self._parse_ipv6(packet[IPv6])

    @staticmethod
    def _parse_ipv4(ip_layer: Any) -> dict[str, Any]:
        """Parse an IPv4 header."""
        proto = ip_layer.proto
        return {
            "version": 4,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ttl": ip_layer.ttl,
            "protocol": proto,
            "protocol_name": IP_PROTOCOLS.get(proto, f"Unknown ({proto})"),
            "header_length": ip_layer.ihl * 4,  # IHL is in 32-bit words
            "total_length": ip_layer.len,
            "flags": str(ip_layer.flags),
        }

    @staticmethod
    def _parse_ipv6(ipv6_layer: Any) -> dict[str, Any]:
        """Parse an IPv6 header."""
        next_header = ipv6_layer.nh
        return {
            "version": 6,
            "src_ip": ipv6_layer.src,
            "dst_ip": ipv6_layer.dst,
            "ttl": ipv6_layer.hlim,  # Hop Limit (equivalent to TTL)
            "protocol": next_header,
            "protocol_name": IP_PROTOCOLS.get(next_header, f"Unknown ({next_header})"),
            "header_length": 40,  # IPv6 header is always 40 bytes
            "total_length": ipv6_layer.plen + 40,  # Payload length + header
            "traffic_class": ipv6_layer.tc,
            "flow_label": ipv6_layer.fl,
        }
