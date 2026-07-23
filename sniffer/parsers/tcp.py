"""
TCP Segment Parser (Layer 4)
=============================

Parses TCP segment headers to extract port numbers, sequence/acknowledgment
numbers, flags, and window size.

"""

from __future__ import annotations

from typing import Any

from sniffer.parsers.base import BaseParser

# Well-known TCP ports → service names
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


class TCPParser(BaseParser):
    """Parses TCP (Layer 4) segment headers.

    Extracts:
        - ``src_port``: Source port number.
        - ``dst_port``: Destination port number.
        - ``src_service``: Service name for source port (if known).
        - ``dst_service``: Service name for destination port (if known).
        - ``seq``: Sequence number.
        - ``ack``: Acknowledgment number.
        - ``flags``: TCP flags as a human-readable string.
        - ``flags_list``: TCP flags as a list of individual flag names.
        - ``window_size``: Receive window size.
        - ``data_offset``: Header length in bytes.
    """

    @property
    def layer_name(self) -> str:
        return "TCP"

    def can_parse(self, packet: Any) -> bool:
        """Check if the packet has a TCP layer."""
        from scapy.layers.inet import TCP

        return packet.haslayer(TCP)

    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract TCP segment fields.

        Args:
            packet: A Scapy packet containing a TCP layer.

        Returns:
            Dictionary with TCP fields.

        Example output::

            {
                "src_port": 54321,
                "dst_port": 443,
                "src_service": "",
                "dst_service": "HTTPS",
                "seq": 1234567890,
                "ack": 987654321,
                "flags": "SYN ACK",
                "flags_list": ["SYN", "ACK"],
                "window_size": 65535,
                "data_offset": 20
            }
        """
        from scapy.layers.inet import TCP

        tcp = packet[TCP]
        flags = tcp.flags
        flags_list = self._decode_flags(flags)

        return {
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "src_service": WELL_KNOWN_PORTS.get(tcp.sport, ""),
            "dst_service": WELL_KNOWN_PORTS.get(tcp.dport, ""),
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags": " ".join(flags_list) if flags_list else "NONE",
            "flags_list": flags_list,
            "window_size": tcp.window,
            "data_offset": tcp.dataofs * 4,  # Data offset is in 32-bit words
        }

    @staticmethod
    def _decode_flags(flags: Any) -> list[str]:
        """Decode TCP flags from Scapy's FlagValue into a list of names.

        Scapy represents TCP flags as a ``FlagValue`` object. We convert
        it to a string and parse individual flag characters.

        Args:
            flags: Scapy's TCP flags value.

        Returns:
            A list of flag names (e.g., ``["SYN", "ACK"]``).
        """
        # Scapy flag characters → full names
        flag_map = {
            "F": "FIN",
            "S": "SYN",
            "R": "RST",
            "P": "PSH",
            "A": "ACK",
            "U": "URG",
            "E": "ECE",
            "C": "CWR",
        }

        flag_str = str(flags)
        return [flag_map.get(ch, ch) for ch in flag_str if ch in flag_map]
