"""
DNS Message Parser
===================

Parses DNS query and response messages to extract domain names,
query types, and answer records.

"""

from __future__ import annotations

from typing import Any

from sniffer.parsers.base import BaseParser

# DNS query type numbers → names
DNS_QUERY_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    255: "ANY",
    257: "CAA",
}

# DNS response codes
DNS_RCODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DNSParser(BaseParser):
    """Parses DNS query and response messages.

    Extracts:
        - ``is_response``: Whether this is a query or response.
        - ``transaction_id``: DNS transaction ID.
        - ``query_name``: The queried domain name.
        - ``query_type``: Numeric query type.
        - ``query_type_name``: Human-readable query type (e.g., "A").
        - ``response_code``: Response code (if response).
        - ``response_code_name``: Human-readable response code.
        - ``answers``: List of answer records (if response).
        - ``answer_count``: Number of answer records.
    """

    @property
    def layer_name(self) -> str:
        return "DNS"

    def can_parse(self, packet: Any) -> bool:
        """Check if the packet has a DNS layer."""
        from scapy.layers.dns import DNS

        return packet.haslayer(DNS)

    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract DNS message fields.

        Args:
            packet: A Scapy packet containing a DNS layer.

        Returns:
            Dictionary with DNS fields.

        Example output (query)::

            {
                "is_response": False,
                "transaction_id": 12345,
                "query_name": "www.google.com",
                "query_type": 1,
                "query_type_name": "A",
                "response_code": 0,
                "response_code_name": "NOERROR",
                "answers": [],
                "answer_count": 0
            }
        """
        from scapy.layers.dns import DNS, DNSQR, DNSRR

        dns = packet[DNS]

        # Determine if this is a query (QR=0) or response (QR=1)
        is_response = dns.qr == 1

        # Extract query information
        query_name = ""
        query_type = 0
        if dns.qdcount > 0 and packet.haslayer(DNSQR):
            qr = packet[DNSQR]
            # Decode query name (Scapy returns bytes with trailing dot)
            raw_name = qr.qname
            if isinstance(raw_name, bytes):
                raw_name = raw_name.decode("utf-8", errors="replace")
            query_name = raw_name.rstrip(".")
            query_type = qr.qtype

        # Extract answers (only present in responses)
        answers = []
        if is_response and dns.ancount > 0 and packet.haslayer(DNSRR):
            answers = self._extract_answers(packet, dns.ancount)

        return {
            "is_response": is_response,
            "transaction_id": dns.id,
            "query_name": query_name,
            "query_type": query_type,
            "query_type_name": DNS_QUERY_TYPES.get(query_type, f"TYPE{query_type}"),
            "response_code": dns.rcode,
            "response_code_name": DNS_RCODES.get(dns.rcode, f"RCODE{dns.rcode}"),
            "answers": answers,
            "answer_count": len(answers),
        }

    @staticmethod
    def _extract_answers(packet: Any, count: int) -> list[dict[str, str]]:
        """Extract answer resource records from a DNS response.

        Iterates through the answer section of a DNS response and
        extracts the record name, type, and data (IP address, CNAME, etc.).

        Args:
            packet: The Scapy packet with DNS answer records.
            count: The number of answer records (from the header).

        Returns:
            A list of dictionaries, each representing one answer record.
        """
        from scapy.layers.dns import DNSRR

        answers = []
        try:
            rr = packet[DNSRR]
            for i in range(min(count, 20)):  # Cap at 20 to prevent DoS
                if rr is None:
                    break

                # Decode record name
                name = rr.rrname
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace").rstrip(".")

                # Decode record data
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="replace")

                answers.append(
                    {
                        "name": str(name),
                        "type": DNS_QUERY_TYPES.get(rr.type, f"TYPE{rr.type}"),
                        "data": str(rdata),
                        "ttl": str(rr.ttl),
                    }
                )

                # Move to next record
                rr = rr.payload
                if not hasattr(rr, "rrname"):
                    break

        except Exception:
            pass  # Best-effort — partial answers are still useful

        return answers
