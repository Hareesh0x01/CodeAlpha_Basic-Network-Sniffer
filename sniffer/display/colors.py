"""
Protocol Color Mapping
=======================

Provides consistent, visually distinct colors for each protocol layer
in the terminal output. Uses the ``rich`` library's color system.

"""

from __future__ import annotations

# Protocol → Rich style string mapping
# These styles are used by the formatter and live view modules.
PROTOCOL_STYLES: dict[str, str] = {
    # Layer 2
    "Ethernet": "dim white",
    # Layer 3
    "IP": "bright_white",
    "ARP": "bold red",
    "ICMP": "bold blue",
    # Layer 4
    "TCP": "bold cyan",
    "UDP": "bold green",
    # Layer 7
    "DNS": "bold yellow",
    "HTTP": "bold magenta",
    # Fallback
    "Unknown": "white",
}

# Protocol → emoji/icon for visual flair in the terminal
PROTOCOL_ICONS: dict[str, str] = {
    "Ethernet": "🔗",
    "IP": "🌐",
    "ARP": "📡",
    "ICMP": "🏓",
    "TCP": "🔒",
    "UDP": "📨",
    "DNS": "📖",
    "HTTP": "🌍",
    "Unknown": "❓",
}


def get_protocol_style(protocol: str) -> str:
    """Get the Rich style string for a protocol.

    Args:
        protocol: The protocol name (e.g., "TCP", "DNS").

    Returns:
        A Rich-compatible style string (e.g., "bold cyan").

    Example:
        >>> from rich import print as rprint
        >>> style = get_protocol_style("TCP")
        >>> rprint(f"[{style}]TCP Packet[/{style}]")
    """
    return PROTOCOL_STYLES.get(protocol, PROTOCOL_STYLES["Unknown"])


def get_protocol_icon(protocol: str) -> str:
    """Get the emoji icon for a protocol.

    Args:
        protocol: The protocol name.

    Returns:
        An emoji string (e.g., "🔒" for TCP).
    """
    return PROTOCOL_ICONS.get(protocol, PROTOCOL_ICONS["Unknown"])


def get_highest_protocol(layers: list[str]) -> str:
    """Determine the highest (most specific) protocol in a packet's layer stack.

    Returns the last layer in the list, which is typically the most
    specific protocol (e.g., DNS rather than UDP, HTTP rather than TCP).

    Args:
        layers: A list of protocol layer names from lowest to highest.

    Returns:
        The highest-level protocol name, or "Unknown" if empty.
    """
    if not layers:
        return "Unknown"
    return layers[-1]
