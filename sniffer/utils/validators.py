"""
Input Validation Helpers
=========================

Provides reusable validation functions for user inputs such as
IP addresses, port numbers, BPF filter expressions, and interface names.

"""

import ipaddress

from sniffer.utils.logger import get_logger

logger = get_logger(__name__)

# ─── Boolean Validators ────────────────────────────────────────────────────


def is_valid_ip(address: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address.

    Uses Python's ``ipaddress`` module for accurate parsing. Supports
    both IPv4 (``192.168.1.1``) and IPv6 (``::1``) formats.

    Args:
        address: The IP address string to validate.

    Returns:
        True if the address is valid, False otherwise.

    Examples:
        >>> is_valid_ip("192.168.1.1")
        True
        >>> is_valid_ip("::1")
        True
        >>> is_valid_ip("999.999.999.999")
        False
        >>> is_valid_ip("not_an_ip")
        False
    """
    try:
        ipaddress.ip_address(address.strip())
        return True
    except ValueError:
        return False


def is_valid_port(port: int | str) -> bool:
    """Check if a value is a valid network port number (1–65535).

    Port 0 is excluded because it's reserved and cannot be filtered
    meaningfully in most BPF contexts.

    Args:
        port: The port number to validate (int or numeric string).

    Returns:
        True if the port is in range 1–65535, False otherwise.

    Examples:
        >>> is_valid_port(80)
        True
        >>> is_valid_port("443")
        True
        >>> is_valid_port(0)
        False
        >>> is_valid_port(70000)
        False
    """
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_bpf(filter_expression: str) -> bool:
    """Check if a BPF filter expression is syntactically valid.

    Attempts to compile the filter using Scapy's internal compiler.
    If compilation succeeds, the filter is valid.

    Args:
        filter_expression: The BPF filter string to validate.

    Returns:
        True if the filter compiles successfully, False otherwise.

    Examples:
        >>> is_valid_bpf("tcp port 80")
        True
        >>> is_valid_bpf("invalid garbage filter")
        False

    Note:
        This function requires Scapy to be installed and may need
        elevated privileges to access the packet filter compiler.
    """
    if not filter_expression or not filter_expression.strip():
        return True  # Empty filter means "capture everything"

    try:
        from scapy.arch import get_if_list
        from scapy.config import conf

        # Use the default interface to attempt filter compilation
        interfaces = get_if_list()
        if not interfaces:
            logger.warning("No interfaces available for BPF validation")
            return True  # Can't validate without interfaces

        # Try to compile the filter — this will raise if invalid

        test_socket = conf.L2listen(
            iface=interfaces[0],
            filter=filter_expression,
        )
        test_socket.close()
        return True
    except Exception as exc:
        logger.debug("BPF filter validation failed: %s", exc)
        return False


def is_valid_interface(interface_name: str) -> bool:
    """Check if a network interface name exists on this system.

    Queries Scapy's interface list and checks for an exact match.

    Args:
        interface_name: The interface name to look up.

    Returns:
        True if the interface exists, False otherwise.
    """
    if not interface_name or not interface_name.strip():
        return False

    try:
        from scapy.arch import get_if_list

        available = get_if_list()
        return interface_name.strip() in available
    except Exception as exc:
        logger.debug("Interface validation failed: %s", exc)
        return False


# ─── Raising Validators (for CLI argument parsing) ──────────────────────────


def validate_ip(address: str) -> str:
    """Validate and return an IP address string, or raise ``ValueError``.

    Designed for use with ``argparse`` ``type=`` parameter.

    Args:
        address: The IP address string to validate.

    Returns:
        The validated IP address string (stripped of whitespace).

    Raises:
        ValueError: If the address is not a valid IPv4 or IPv6 address.
    """
    address = address.strip()
    if not is_valid_ip(address):
        raise ValueError(
            f"'{address}' is not a valid IP address. "
            "Expected format: 192.168.1.1 (IPv4) or ::1 (IPv6)"
        )
    return address


def validate_port(port: str) -> int:
    """Validate and return a port number, or raise ``ValueError``.

    Designed for use with ``argparse`` ``type=`` parameter.

    Args:
        port: The port number as a string.

    Returns:
        The validated port number as an integer.

    Raises:
        ValueError: If the port is not a valid number in range 1–65535.
    """
    if not is_valid_port(port):
        raise ValueError(
            f"'{port}' is not a valid port number. "
            "Expected: integer between 1 and 65535"
        )
    return int(port)
