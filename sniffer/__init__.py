"""
Basic Network Sniffer
=====================

An educational network packet sniffer built with Python and Scapy.
Captures real packets from a user-selected network interface,
parses protocol layers, and presents results in a clean terminal dashboard.

**Educational purpose only.** Unauthorized packet capture is illegal.

Usage:
    python -m sniffer capture
    python -m sniffer list-interfaces
    python -m sniffer --help
"""

__version__ = "1.0.0"
__author__ = "Network Sniffer Educational Project"
__license__ = "MIT"

# Public API exports
__all__ = ["__version__", "__author__", "__license__"]
