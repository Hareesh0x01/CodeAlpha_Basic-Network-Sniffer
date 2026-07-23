"""
ARP Message Parser
===================

Parses ARP (Address Resolution Protocol) messages to extract
MAC and IP address mappings.

"""

from __future__ import annotations

from typing import Any

from sniffer.parsers.base import BaseParser

# ARP operation codes
ARP_OPERATIONS: dict[int, str] = {
    1: "Request (who-has)",
    2: "Reply (is-at)",
    3: "RARP Request",
    4: "RARP Reply",
}


class ARPParser(BaseParser):
    """Parses ARP (Address Resolution Protocol) messages.

    Extracts:
        - ``operation``: ARP operation code (1=request, 2=reply).
        - ``operation_name``: Human-readable operation name.
        - ``sender_mac``: MAC address of the sender.
        - ``sender_ip``: IP address of the sender.
        - ``target_mac``: MAC address of the target.
        - ``target_ip``: IP address of the target.
        - ``summary``: One-line human-readable summary.
    """

    @property
    def layer_name(self) -> str:
        return "ARP"

    def can_parse(self, packet: Any) -> bool:
        """Check if the packet has an ARP layer."""
        from scapy.layers.l2 import ARP

        return packet.haslayer(ARP)

    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract ARP message fields.

        Args:
            packet: A Scapy packet containing an ARP layer.

        Returns:
            Dictionary with ARP fields.

        Example output (request)::

            {
                "operation": 1,
                "operation_name": "Request (who-has)",
                "sender_mac": "aa:bb:cc:dd:ee:ff",
                "sender_ip": "192.168.1.100",
                "target_mac": "00:00:00:00:00:00",
                "target_ip": "192.168.1.1",
                "summary": "Who has 192.168.1.1? Tell 192.168.1.100"
            }
        """
        from scapy.layers.l2 import ARP

        arp = packet[ARP]
        op = arp.op

        # Build a human-readable summary
        if op == 1:
            summary = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif op == 2:
            summary = f"{arp.psrc} is at {arp.hwsrc}"
        else:
            summary = f"ARP op={op} {arp.psrc} → {arp.pdst}"

        return {
            "operation": op,
            "operation_name": ARP_OPERATIONS.get(op, f"Unknown ({op})"),
            "sender_mac": arp.hwsrc,
            "sender_ip": arp.psrc,
            "target_mac": arp.hwdst,
            "target_ip": arp.pdst,
            "summary": summary,
        }
