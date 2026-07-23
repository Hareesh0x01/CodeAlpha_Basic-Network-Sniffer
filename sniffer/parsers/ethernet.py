"""
Ethernet Frame Parser (Layer 2)
================================

Parses Ethernet frames to extract source/destination MAC addresses
and the EtherType field that identifies the encapsulated protocol.

"""

from __future__ import annotations

from typing import Any

from sniffer.parsers.base import BaseParser

# EtherType → human-readable protocol name
ETHER_TYPES: dict[int, str] = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN (802.1Q)",
    0x88CC: "LLDP",
    0x8847: "MPLS",
    0x88A8: "802.1ad (QinQ)",
}


class EthernetParser(BaseParser):
    """Parses Ethernet (Layer 2) frames.

    Extracts:
        - ``src_mac``: Source MAC address.
        - ``dst_mac``: Destination MAC address.
        - ``ether_type``: Numeric EtherType value.
        - ``ether_type_name``: Human-readable protocol name.
    """

    @property
    def layer_name(self) -> str:
        return "Ethernet"

    def can_parse(self, packet: Any) -> bool:
        """Check if the packet has an Ethernet layer."""
        from scapy.layers.l2 import Ether

        return packet.haslayer(Ether)

    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract Ethernet frame fields.

        Args:
            packet: A Scapy packet containing an Ethernet layer.

        Returns:
            Dictionary with Ethernet fields.

        Example output::

            {
                "src_mac": "aa:bb:cc:dd:ee:ff",
                "dst_mac": "11:22:33:44:55:66",
                "ether_type": 2048,
                "ether_type_name": "IPv4"
            }
        """
        from scapy.layers.l2 import Ether

        eth = packet[Ether]
        ether_type = eth.type

        return {
            "src_mac": eth.src,
            "dst_mac": eth.dst,
            "ether_type": ether_type,
            "ether_type_name": ETHER_TYPES.get(
                ether_type, f"Unknown (0x{ether_type:04X})"
            ),
        }
