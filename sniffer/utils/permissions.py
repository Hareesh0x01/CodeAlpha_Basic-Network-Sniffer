"""
OS Privilege Checks
====================

Packet capture requires elevated privileges on all operating systems.
This module checks whether the application is running with sufficient
permissions and provides platform-specific remediation instructions.

Platform Requirements:
    - **Windows**: Must run as Administrator. Also requires Npcap.
    - **Linux**: Must run as root (``sudo``) or have ``CAP_NET_RAW``.
    - **macOS**: Must run as root (``sudo``).

"""

import os
import platform
import sys

from sniffer.utils.exceptions import InsufficientPrivilegesError, NpcapNotFoundError
from sniffer.utils.logger import get_logger

logger = get_logger(__name__)


def check_privileges() -> None:
    """Verify that the application has sufficient privileges for packet capture.

    Raises:
        InsufficientPrivilegesError: If not running as admin/root.
        NpcapNotFoundError: If Npcap is not installed on Windows.

    Example:
        >>> from sniffer.utils.permissions import check_privileges
        >>> check_privileges()  # Raises if not elevated
    """
    current_os = platform.system()
    logger.debug("Checking privileges on %s", current_os)

    if current_os == "Windows":
        _check_windows_privileges()
    elif current_os in ("Linux", "Darwin"):
        _check_unix_privileges()
    else:
        logger.warning(
            "Unknown OS '%s'. Cannot verify privileges — "
            "capture may fail if not running as admin/root.",
            current_os,
        )


def _check_windows_privileges() -> None:
    """Check for Administrator privileges and Npcap on Windows.

    Uses the Win32 API via ``ctypes`` to check if the current process
    token has the Administrator SID.

    Raises:
        InsufficientPrivilegesError: If not running as Administrator.
        NpcapNotFoundError: If Npcap is not installed.
    """
    import ctypes

    try:
        is_admin: bool = ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
    except (AttributeError, OSError) as exc:
        logger.error("Could not check Windows admin status: %s", exc)
        is_admin = False

    if not is_admin:
        logger.critical("Not running as Administrator on Windows")
        raise InsufficientPrivilegesError(
            "This application must be run as Administrator on Windows. "
            "Right-click your terminal and select 'Run as Administrator'."
        )

    logger.info("Running with Administrator privileges ✓")

    # Check for Npcap installation
    _check_npcap()


def _check_npcap() -> None:
    """Verify that Npcap is installed on Windows.

    Checks if Scapy was able to load the pcap provider. If it wasn't,
    it usually means Npcap is missing or not installed in WinPcap API-compatible mode.

    Raises:
        NpcapNotFoundError: If Npcap is not detected.
    """
    try:
        from scapy.config import conf

        if not conf.use_pcap:
            logger.critical("Npcap not found or not in WinPcap API-compatible mode.")
            raise NpcapNotFoundError(
                "Npcap or WinPcap is required for packet capture on Windows but was not found.\n"
                "Please download and install Npcap from https://npcap.com/.\n"
                "IMPORTANT: During installation, ensure you check the box for "
                "'Install Npcap in WinPcap API-compatible Mode'."
            )
        logger.info("Npcap (WinPcap API-compatible mode) detected ✓")
    except ImportError:
        logger.critical("Npcap not found and Scapy cannot access capture interface")
        raise NpcapNotFoundError(
            "Npcap or WinPcap is required for packet capture on Windows but was not found.\n"
            "Please download and install Npcap from https://npcap.com/.\n"
            "IMPORTANT: During installation, ensure you check the box for "
            "'Install Npcap in WinPcap API-compatible Mode'."
        )
    except Exception as exc:
        # Scapy might raise other errors if Npcap is partially installed
        logger.warning("Npcap check encountered an issue: %s", exc)


def _check_unix_privileges() -> None:
    """Check for root or ``CAP_NET_RAW`` on Linux/macOS.

    On Unix systems, raw socket access requires either:
    1. Running as root (``euid == 0``), or
    2. Having the ``CAP_NET_RAW`` capability set on the Python binary.

    Raises:
        InsufficientPrivilegesError: If not running with sufficient privileges.
    """
    if os.geteuid() == 0:  # type: ignore[attr-defined]
        logger.info("Running as root ✓")
        return

    # Check for CAP_NET_RAW capability (Linux only)
    if platform.system() == "Linux" and _has_cap_net_raw():
        logger.info("CAP_NET_RAW capability detected ✓")
        return

    logger.critical("Not running as root and no CAP_NET_RAW capability")
    raise InsufficientPrivilegesError(
        "This application requires root privileges. "
        f"Run with: sudo {sys.executable} -m sniffer"
    )


def _has_cap_net_raw() -> bool:
    """Check if the Python binary has the ``CAP_NET_RAW`` capability.

    Uses ``/sbin/getcap`` to inspect the capabilities of the Python
    executable. This is a Linux-specific feature.

    Returns:
        True if ``CAP_NET_RAW`` is set, False otherwise.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["/sbin/getcap", sys.executable],
            capture_output=True,
            text=True,
            timeout=5,
        )
        has_cap = "cap_net_raw" in result.stdout.lower()
        if has_cap:
            logger.debug("getcap output: %s", result.stdout.strip())
        return has_cap
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("Could not check capabilities: %s", exc)
        return False
