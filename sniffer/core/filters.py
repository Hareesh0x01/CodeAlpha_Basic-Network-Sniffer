"""
BPF Filter Builder & Validation
=================================

Constructs Berkeley Packet Filter (BPF) expressions from user-friendly
parameters. BPF filters are applied at the kernel level to reduce the
volume of packets delivered to userspace.

"""

from __future__ import annotations

from sniffer.utils.exceptions import FilterError
from sniffer.utils.logger import get_logger
from sniffer.utils.validators import is_valid_ip, is_valid_port

logger = get_logger(__name__)

# Protocols supported by BPF filters
SUPPORTED_PROTOCOLS = frozenset(
    {
        "tcp",
        "udp",
        "icmp",
        "arp",
        "ip",
        "ip6",
        "ether",
        "vlan",
        "stp",
    }
)


class FilterBuilder:
    """Builds BPF filter expressions from user-friendly parameters.

    Uses the Builder pattern to construct complex filters step by step.
    Each method returns ``self`` for chaining.

    Example:
        >>> fb = FilterBuilder()
        >>> bpf = fb.protocol("tcp").port(80).host("192.168.1.1").build()
        >>> print(bpf)
        'tcp and port 80 and host 192.168.1.1'

        >>> bpf = FilterBuilder().protocol("udp").port(53).build()
        >>> print(bpf)
        'udp and port 53'

        >>> bpf = FilterBuilder.from_raw("tcp port 80 or udp port 53")
        >>> print(bpf)
        'tcp port 80 or udp port 53'
    """

    def __init__(self) -> None:
        """Initialize an empty filter builder."""
        self._parts: list[str] = []

    def protocol(self, proto: str) -> FilterBuilder:
        """Add a protocol filter (e.g., ``tcp``, ``udp``, ``icmp``).

        Args:
            proto: The protocol name (case-insensitive).

        Returns:
            ``self`` for method chaining.

        Raises:
            FilterError: If the protocol is not recognized.
        """
        proto = proto.strip().lower()
        if proto not in SUPPORTED_PROTOCOLS:
            raise FilterError(
                f"Unsupported protocol: '{proto}'",
                details=f"Supported protocols: {', '.join(sorted(SUPPORTED_PROTOCOLS))}",
            )
        self._parts.append(proto)
        logger.debug("Filter: added protocol '%s'", proto)
        return self

    def port(self, port_number: int | str) -> FilterBuilder:
        """Add a port filter (e.g., ``port 80``, ``port 443``).

        This matches both source and destination ports. For directional
        filtering, use ``src_port()`` or ``dst_port()``.

        Args:
            port_number: The port number (1–65535).

        Returns:
            ``self`` for method chaining.

        Raises:
            FilterError: If the port number is invalid.
        """
        if not is_valid_port(port_number):
            raise FilterError(
                f"Invalid port number: '{port_number}'",
                details="Port must be an integer between 1 and 65535.",
            )
        self._parts.append(f"port {int(port_number)}")
        logger.debug("Filter: added port %s", port_number)
        return self

    def src_port(self, port_number: int | str) -> FilterBuilder:
        """Add a source port filter.

        Args:
            port_number: The source port number (1–65535).

        Returns:
            ``self`` for method chaining.
        """
        if not is_valid_port(port_number):
            raise FilterError(f"Invalid source port: '{port_number}'")
        self._parts.append(f"src port {int(port_number)}")
        return self

    def dst_port(self, port_number: int | str) -> FilterBuilder:
        """Add a destination port filter.

        Args:
            port_number: The destination port number (1–65535).

        Returns:
            ``self`` for method chaining.
        """
        if not is_valid_port(port_number):
            raise FilterError(f"Invalid destination port: '{port_number}'")
        self._parts.append(f"dst port {int(port_number)}")
        return self

    def host(self, ip_address: str) -> FilterBuilder:
        """Add a host filter — matches traffic to/from the given IP.

        Args:
            ip_address: An IPv4 or IPv6 address.

        Returns:
            ``self`` for method chaining.

        Raises:
            FilterError: If the IP address is invalid.
        """
        ip_address = ip_address.strip()
        if not is_valid_ip(ip_address):
            raise FilterError(
                f"Invalid IP address: '{ip_address}'",
                details="Expected format: 192.168.1.1 (IPv4) or ::1 (IPv6)",
            )
        self._parts.append(f"host {ip_address}")
        logger.debug("Filter: added host '%s'", ip_address)
        return self

    def src_host(self, ip_address: str) -> FilterBuilder:
        """Add a source host filter.

        Args:
            ip_address: The source IP address.

        Returns:
            ``self`` for method chaining.
        """
        ip_address = ip_address.strip()
        if not is_valid_ip(ip_address):
            raise FilterError(f"Invalid source IP: '{ip_address}'")
        self._parts.append(f"src host {ip_address}")
        return self

    def dst_host(self, ip_address: str) -> FilterBuilder:
        """Add a destination host filter.

        Args:
            ip_address: The destination IP address.

        Returns:
            ``self`` for method chaining.
        """
        ip_address = ip_address.strip()
        if not is_valid_ip(ip_address):
            raise FilterError(f"Invalid destination IP: '{ip_address}'")
        self._parts.append(f"dst host {ip_address}")
        return self

    def net(self, network: str) -> FilterBuilder:
        """Add a network/subnet filter (e.g., ``net 192.168.1.0/24``).

        Args:
            network: A network address with optional CIDR notation.

        Returns:
            ``self`` for method chaining.
        """
        self._parts.append(f"net {network.strip()}")
        logger.debug("Filter: added network '%s'", network)
        return self

    def build(self) -> str:
        """Compile all filter parts into a single BPF expression.

        Parts are joined with ``and`` — all conditions must match.

        Returns:
            The complete BPF filter string, or empty string if no
            filters were added (capture everything).

        Example:
            >>> FilterBuilder().protocol("tcp").port(80).build()
            'tcp and port 80'
        """
        if not self._parts:
            logger.debug("No filter parts — capturing all traffic")
            return ""

        bpf = " and ".join(self._parts)
        logger.info("Built BPF filter: '%s'", bpf)
        return bpf

    @staticmethod
    def from_raw(raw_filter: str) -> str:
        """Accept a raw BPF filter string from an advanced user.

        This performs basic sanity checking but passes the filter
        through largely unchanged, since advanced users may need
        complex expressions that the builder doesn't support.

        Args:
            raw_filter: A raw BPF filter expression.

        Returns:
            The sanitized BPF filter string.

        Raises:
            FilterError: If the filter is obviously malformed.
        """
        raw_filter = raw_filter.strip()
        if not raw_filter:
            return ""

        # Basic sanity checks — catch common mistakes
        dangerous_keywords = ["drop", "reject", "modify", "rewrite"]
        for keyword in dangerous_keywords:
            if keyword in raw_filter.lower():
                raise FilterError(
                    f"BPF filters cannot contain '{keyword}'",
                    details="BPF is a read-only filter — it cannot modify packets.",
                )

        logger.info("Using raw BPF filter: '%s'", raw_filter)
        return raw_filter

    def reset(self) -> FilterBuilder:
        """Clear all filter parts and start fresh.

        Returns:
            ``self`` for method chaining.
        """
        self._parts.clear()
        logger.debug("Filter builder reset")
        return self
