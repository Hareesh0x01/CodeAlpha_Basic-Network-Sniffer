"""
Network Interface Discovery & Selection
=========================================

Discovers available network interfaces using Scapy and presents them
to the user for selection. Works cross-platform (Windows/Linux/macOS).

"""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass

from sniffer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class NetworkInterface:
    """Represents a single network interface on the system.

    Attributes:
        name: The OS-level interface name (e.g., ``eth0``, ``Wi-Fi``).
        description: A human-readable description (may be empty on Linux).
        ip_address: The IPv4 address assigned to this interface, or "N/A".
        mac_address: The MAC (hardware) address, or "N/A".
        is_up: Whether the interface is currently active/enabled.
        is_loopback: Whether this is the loopback interface.
    """

    name: str
    description: str = ""
    ip_address: str = "N/A"
    mac_address: str = "N/A"
    is_up: bool = False
    is_loopback: bool = False

    def display_name(self) -> str:
        """Return a formatted string for display in the interface menu.

        Returns:
            A string like: ``Wi-Fi (192.168.1.100) [UP]``
        """
        status = "UP" if self.is_up else "DOWN"
        desc = f" — {self.description}" if self.description else ""
        return f"{self.name}{desc} ({self.ip_address}) [{status}]"


class InterfaceManager:
    """Discovers and manages network interfaces via Scapy.

    This class provides a cross-platform API for listing interfaces,
    looking up interfaces by name, and validating user selections.

    Example:
        >>> manager = InterfaceManager()
        >>> interfaces = manager.list_interfaces()
        >>> for iface in interfaces:
        ...     print(iface.display_name())
        Wi-Fi — Intel Wi-Fi 6 (192.168.1.100) [UP]
        Loopback Pseudo-Interface 1 (127.0.0.1) [UP]
    """

    def __init__(self) -> None:
        """Initialize the interface manager and discover interfaces."""
        self._interfaces: list[NetworkInterface] = []
        self._discover()

    def _discover(self) -> None:
        """Discover all network interfaces using Scapy.

        Scapy's ``IFACES`` registry provides cross-platform interface
        discovery. On Windows, it resolves GUID-based names to friendly
        names. On Linux, it reads from ``/sys/class/net/``.
        """
        try:
            from scapy.interfaces import IFACES

            logger.debug("Discovering network interfaces via Scapy IFACES...")

            for iface_id, iface_obj in IFACES.items():
                try:
                    # Extract interface properties safely
                    name = self._get_iface_name(iface_obj, iface_id)
                    description = getattr(iface_obj, "description", "") or ""
                    ip_addr = getattr(iface_obj, "ip", "N/A") or "N/A"
                    mac_addr = getattr(iface_obj, "mac", "N/A") or "N/A"
                    is_up = bool(getattr(iface_obj, "is_up", False))

                    # Detect loopback interfaces
                    is_loopback = (
                        "loopback" in name.lower()
                        or "loopback" in description.lower()
                        or ip_addr == "127.0.0.1"
                        or name == "lo"
                    )

                    net_iface = NetworkInterface(
                        name=name,
                        description=description,
                        ip_address=ip_addr,
                        mac_address=mac_addr,
                        is_up=is_up,
                        is_loopback=is_loopback,
                    )
                    self._interfaces.append(net_iface)
                    logger.debug("Found interface: %s", net_iface.display_name())

                except Exception as exc:
                    logger.warning("Could not parse interface '%s': %s", iface_id, exc)
                    continue

        except ImportError as exc:
            logger.error("Scapy is not installed or not accessible: %s", exc)
        except Exception as exc:
            logger.error("Interface discovery failed: %s", exc)

        # Fallback for Windows if Scapy failed to find anything
        if not self._interfaces and platform.system() == "Windows":
            logger.warning(
                "Scapy found no interfaces. Attempting Windows fallback discovery..."
            )
            self._fallback_discover()

    def _fallback_discover(self) -> None:
        """Attempt to discover interfaces using native OS commands.

        Used on Windows when Scapy's IFACES is empty (often due to missing
        Npcap or driver issues). This ensures the user at least sees available
        connection names.
        """
        try:
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Parse output lines like:
            # Idx     Met         MTU          State                Name
            # ---  ----------  ----------  ------------  ---------------------------
            #  11          25        1500  connected     Wi-Fi
            #   1          75  4294967295  connected     Loopback Pseudo-Interface 1
            for line in result.stdout.splitlines():
                match = re.search(r"^\s*\d+\s+\d+\s+\d+\s+(\w+)\s+(.+)$", line)
                if match:
                    state, name = match.groups()
                    name = name.strip()
                    is_up = state.lower() == "connected"
                    is_loopback = "loopback" in name.lower()

                    net_iface = NetworkInterface(
                        name=name,
                        description="Discovered via fallback (netsh)",
                        is_up=is_up,
                        is_loopback=is_loopback,
                    )
                    self._interfaces.append(net_iface)
                    logger.debug("Fallback discovered interface: %s", name)
        except Exception as exc:
            logger.error("Fallback discovery also failed: %s", exc)

    @staticmethod
    def _get_iface_name(iface_obj: object, fallback: object) -> str:
        """Extract the best human-readable name for an interface.

        On Windows, Scapy interfaces may have a ``name`` attribute with
        a GUID. We prefer ``description`` or ``network_name`` when available.

        Args:
            iface_obj: The Scapy interface object.
            fallback: The key from the IFACES dict (used if no name found).

        Returns:
            The human-readable interface name.
        """
        # Try network_name first (Windows-friendly name)
        name = getattr(iface_obj, "network_name", None)
        if name:
            return str(name)

        # Fall back to name attribute
        name = getattr(iface_obj, "name", None)
        if name:
            return str(name)

        # Last resort: use the dict key
        return str(fallback)

    def list_interfaces(self, include_down: bool = False) -> list[NetworkInterface]:
        """Return a list of discovered network interfaces.

        Args:
            include_down: If True, include interfaces that are currently
                down (disabled). Default is False (only active interfaces).

        Returns:
            A list of ``NetworkInterface`` objects, sorted with active
            non-loopback interfaces first.
        """
        interfaces = self._interfaces
        if not include_down:
            interfaces = [iface for iface in interfaces if iface.is_up]

        # Sort: non-loopback UP interfaces first, then loopback, then down
        return sorted(
            interfaces,
            key=lambda i: (not i.is_up, i.is_loopback, i.name),
        )

    def get_interface(self, name: str) -> NetworkInterface:
        """Look up an interface by name.

        Performs a case-insensitive search across interface names and
        descriptions.

        Args:
            name: The interface name to look up.

        Returns:
            The matching ``NetworkInterface`` object.

        Raises:
            InterfaceError: If no interface with that name is found.
        """
        name_lower = name.strip().lower()
        for iface in self._interfaces:
            if (
                iface.name.lower() == name_lower
                or iface.description.lower() == name_lower
            ):
                return iface

        # If not found in the list, we don't block it. Scapy might still be
        # able to bind to it even if it failed to list it. We trust the user.
        logger.info(
            "Interface '%s' not in discovered list; treating as manual override.", name
        )
        return NetworkInterface(
            name=name,
            description="Manually specified interface",
            is_up=True,
        )

    def get_default_interface(self) -> NetworkInterface | None:
        """Return the system's default (most likely active) interface.

        Heuristic: the first non-loopback, UP interface with an IP address.

        Returns:
            The default ``NetworkInterface``, or None if no suitable
            interface is found.
        """
        for iface in self.list_interfaces():
            if not iface.is_loopback and iface.ip_address != "N/A":
                return iface
        return None
