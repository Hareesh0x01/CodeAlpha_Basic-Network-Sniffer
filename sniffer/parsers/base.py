"""
Abstract Base Parser
=====================

Defines the contract that all protocol parsers must follow.
Using an abstract base class (ABC) ensures consistency across parsers
and enables the registry pattern for automatic parser discovery.

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sniffer.utils.logger import get_logger

logger = get_logger(__name__)


class BaseParser(ABC):
    """Abstract base class for all protocol parsers.

    Every parser must implement:
    - ``layer_name``: The protocol name (e.g., ``"TCP"``).
    - ``can_parse(packet)``: Check if this parser applies to the packet.
    - ``parse(packet)``: Extract structured data from the packet.

    Example (implementing a parser):
        >>> class MyProtocolParser(BaseParser):
        ...     @property
        ...     def layer_name(self) -> str:
        ...         return "MyProtocol"
        ...
        ...     def can_parse(self, packet) -> bool:
        ...         return packet.haslayer("MyProtocol")
        ...
        ...     def parse(self, packet) -> dict[str, Any]:
        ...         layer = packet["MyProtocol"]
        ...         return {"field1": layer.field1, "field2": layer.field2}
    """

    @property
    @abstractmethod
    def layer_name(self) -> str:
        """Return the human-readable name of the protocol layer.

        Returns:
            A string like ``"Ethernet"``, ``"IP"``, ``"TCP"``, ``"DNS"``.
        """

    @abstractmethod
    def can_parse(self, packet: Any) -> bool:
        """Check whether this parser can handle the given packet.

        This method should be fast — it typically just checks if the
        packet has the relevant Scapy layer using ``packet.haslayer()``.

        Args:
            packet: A raw Scapy packet object.

        Returns:
            True if this parser can extract data from the packet.
        """

    @abstractmethod
    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract structured data from the packet.

        This is the core parsing logic. It accesses Scapy's packet
        layers and extracts relevant fields into a flat dictionary.

        Args:
            packet: A raw Scapy packet object.

        Returns:
            A dictionary with extracted fields. Keys should be
            descriptive (e.g., ``"src_ip"``, ``"dst_port"``).

        Raises:
            Exception: If parsing fails (caught by ``parse_safe()``).
        """

    def parse_safe(self, packet: Any) -> dict[str, Any] | None:
        """Safely parse a packet, catching and logging any exceptions.

        This wrapper ensures that a single parser failure never crashes
        the entire capture session. If ``parse()`` raises, the error is
        logged and ``None`` is returned.

        Args:
            packet: A raw Scapy packet object.

        Returns:
            The parsed data dictionary, or None if parsing failed.
        """
        try:
            if not self.can_parse(packet):
                return None
            return self.parse(packet)
        except Exception as exc:
            logger.warning(
                "Parser '%s' failed: %s",
                self.layer_name,
                exc,
                exc_info=logger.isEnabledFor(10),  # DEBUG = 10
            )
            return None
