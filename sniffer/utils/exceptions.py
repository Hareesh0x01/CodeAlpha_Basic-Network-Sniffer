"""
Custom Exception Hierarchy
===========================

Defines all application-specific exceptions for the Basic Network Sniffer.
Every exception inherits from ``SnifferError`` so callers can catch all
sniffer-related errors with a single ``except SnifferError`` block.

Hierarchy::

    SnifferError (base)
    ├── InsufficientPrivilegesError  — Not running as admin/root
    ├── InterfaceError               — Interface not found or unavailable
    │   └── NpcapNotFoundError       — Npcap not installed (Windows)
    ├── CaptureError                 — Scapy sniff failure
    │   └── CaptureTimeoutError      — No packets in timeout window
    ├── FilterError                  — Invalid BPF filter syntax
    ├── ParserError                  — Malformed packet during parsing
    └── ExportError                  — File write / serialization failure
"""


class SnifferError(Exception):
    """Base exception for all sniffer-related errors.

    All custom exceptions in this project inherit from ``SnifferError``.
    This allows callers to catch every sniffer error with a single handler.

    Args:
        message: A human-readable description of the error.
        details: Optional additional context (e.g., the raw OS error).
    """

    def __init__(self, message: str, details: str | None = None) -> None:
        self.message = message
        self.details = details
        full_message = f"{message} — {details}" if details else message
        super().__init__(full_message)


# ─── Privilege Errors ───────────────────────────────────────────────────────


class InsufficientPrivilegesError(SnifferError):
    """Raised when the application is not running with admin/root privileges.

    Packet capture requires elevated permissions on all platforms:
    - Windows: Run as Administrator
    - Linux/macOS: Run with ``sudo`` or set ``CAP_NET_RAW``
    """

    def __init__(
        self, message: str = "Insufficient privileges for packet capture"
    ) -> None:
        super().__init__(
            message,
            details="Run as Administrator (Windows) or with sudo (Linux/macOS).",
        )


# ─── Interface Errors ───────────────────────────────────────────────────────


class InterfaceError(SnifferError):
    """Raised when a network interface is not found or unavailable.

    Common causes:
    - The user specified a non-existent interface name.
    - The interface exists but is down (disabled).
    - No interfaces are available at all.
    """

    pass


class NpcapNotFoundError(InterfaceError):
    """Raised when Npcap is not installed on Windows.

    Scapy on Windows requires Npcap (https://npcap.com/) to capture packets.
    This is the modern replacement for WinPcap.
    """

    def __init__(self, message: str | None = None, details: str | None = None) -> None:
        super().__init__(
            message or "Npcap is not installed",
            details=details
            or (
                "Download and install Npcap from https://npcap.com/ "
                "with 'WinPcap API-compatible Mode' enabled, then restart."
            ),
        )


# ─── Capture Errors ─────────────────────────────────────────────────────────


class CaptureError(SnifferError):
    """Raised when the packet capture engine encounters a failure.

    This wraps Scapy errors and OS-level socket errors that occur
    during the ``sniff()`` call.
    """

    pass


class CaptureTimeoutError(CaptureError):
    """Raised when no packets are received within the timeout window.

    This may indicate:
    - The selected interface has no traffic.
    - The BPF filter is too restrictive.
    - The interface is disconnected.
    """

    def __init__(self, timeout_seconds: int) -> None:
        super().__init__(
            f"No packets captured within {timeout_seconds} seconds",
            details="Check interface connectivity and BPF filter settings.",
        )


# ─── Filter Errors ──────────────────────────────────────────────────────────


class FilterError(SnifferError):
    """Raised when a BPF filter expression is invalid.

    BPF (Berkeley Packet Filter) syntax is used to filter traffic
    before it reaches the application. An invalid filter will prevent
    capture from starting.

    Example valid filters:
        ``tcp port 80``
        ``udp and host 192.168.1.1``
        ``icmp``
    """

    pass


# ─── Parser Errors ──────────────────────────────────────────────────────────


class ParserError(SnifferError):
    """Raised when a protocol parser fails to process a packet.

    Parser errors are **non-fatal** — the capture engine catches them,
    logs a warning, and continues processing subsequent packets.
    A single malformed packet should never crash the capture session.
    """

    pass


# ─── Export Errors ──────────────────────────────────────────────────────────


class ExportError(SnifferError):
    """Raised when exporting captured data fails.

    Common causes:
    - Output directory does not exist.
    - Insufficient disk permissions.
    - Disk is full.
    - Serialization error (unexpected data types).
    """

    pass
