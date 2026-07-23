"""
Packet Capture Engine
======================

The heart of the sniffer — wraps Scapy's ``sniff()`` function with
start/stop controls, a packet callback pipeline, and thread-safe
packet storage.

"""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Callable

from sniffer.utils.exceptions import CaptureError
from sniffer.utils.logger import get_logger

logger = get_logger(__name__)

# Type alias for packet callback functions
# Each callback receives the raw Scapy packet and the parsed data dict
PacketCallback = Callable[[Any, dict[str, Any]], None]


@dataclass
class CaptureStats:
    """Live statistics for the current capture session.

    Tracks total counters, per-protocol breakdowns, top source/destination
    IPs, and instantaneous packet rate over a sliding window.

    These counters are updated in real-time as packets are captured.
    Thread-safe via atomic integer operations (CPython GIL).

    Attributes:
        packets_captured: Total number of packets captured.
        bytes_captured: Total bytes across all captured packets.
        start_time: Unix timestamp when capture started.
        end_time: Unix timestamp when capture stopped (0 if running).
        packets_dropped: Packets that could not be parsed.
        protocol_counts: Per-protocol packet counters (e.g., {"TCP": 150, "UDP": 30}).
        protocol_bytes: Per-protocol byte counters.
        src_ip_counts: Counter of source IP addresses.
        dst_ip_counts: Counter of destination IP addresses.
    """

    packets_captured: int = 0
    bytes_captured: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    packets_dropped: int = 0

    # Per-protocol breakdown
    protocol_counts: Counter = field(default_factory=Counter)
    protocol_bytes: Counter = field(default_factory=Counter)

    # Top talkers (source/destination IP frequency)
    src_ip_counts: Counter = field(default_factory=Counter)
    dst_ip_counts: Counter = field(default_factory=Counter)

    # Sliding window for instantaneous rate (timestamps of recent packets)
    _recent_timestamps: deque = field(default_factory=lambda: deque(maxlen=500))

    @property
    def duration(self) -> float:
        """Return the duration of the capture session in seconds."""
        if self.start_time == 0:
            return 0.0
        end = self.end_time if self.end_time > 0 else time.time()
        return end - self.start_time

    @property
    def packets_per_second(self) -> float:
        """Return the average capture rate in packets per second."""
        duration = self.duration
        if duration <= 0:
            return 0.0
        return self.packets_captured / duration

    @property
    def instantaneous_rate(self) -> float:
        """Return the instantaneous packet rate over the last 5 seconds.

        Uses a sliding window of recent packet timestamps to calculate
        the current capture rate, which is more responsive than the
        lifetime average.

        Returns:
            Packets per second over the last 5 seconds.
        """
        if len(self._recent_timestamps) < 2:
            return 0.0
        now = time.time()
        window = 5.0  # 5-second sliding window
        cutoff = now - window
        # Count packets within the window
        recent_count = sum(1 for ts in self._recent_timestamps if ts >= cutoff)
        return recent_count / window

    @property
    def bytes_per_second(self) -> float:
        """Return the average data rate in bytes per second."""
        duration = self.duration
        if duration <= 0:
            return 0.0
        return self.bytes_captured / duration

    def record_packet(
        self, layers: list[str], size: int, src_ip: str, dst_ip: str
    ) -> None:
        """Record a packet's metadata into all statistical counters.

        Called by the capture handler for each packet. Updates protocol
        counters, IP counters, and the sliding rate window.

        Args:
            layers: Protocol layer names (e.g., ["Ethernet", "IP", "TCP"]).
            size: Packet size in bytes.
            src_ip: Source IP address (or empty string).
            dst_ip: Destination IP address (or empty string).
        """
        # Record timestamp for instantaneous rate
        self._recent_timestamps.append(time.time())

        # Update per-protocol counters using the highest-level protocol
        if layers:
            top_protocol = layers[-1]  # Highest layer = most specific
            self.protocol_counts[top_protocol] += 1
            self.protocol_bytes[top_protocol] += size

        # Update IP counters
        if src_ip:
            self.src_ip_counts[src_ip] += 1
        if dst_ip:
            self.dst_ip_counts[dst_ip] += 1

    def get_protocol_distribution(self) -> list[tuple[str, int, int]]:
        """Return protocol distribution sorted by packet count.

        Returns:
            List of (protocol_name, packet_count, byte_count) tuples,
            sorted by packet count descending.
        """
        return [
            (proto, count, self.protocol_bytes.get(proto, 0))
            for proto, count in self.protocol_counts.most_common()
        ]

    def get_top_talkers(self, n: int = 5) -> dict[str, list[tuple[str, int]]]:
        """Return the top N source and destination IPs by packet count.

        Args:
            n: Number of top talkers to return.

        Returns:
            A dict with 'sources' and 'destinations' keys, each containing
            a list of (ip, count) tuples.
        """
        return {
            "sources": self.src_ip_counts.most_common(n),
            "destinations": self.dst_ip_counts.most_common(n),
        }


class PacketCapture:
    """Manages packet capture using Scapy's sniff engine.

    This class provides a high-level API for starting, stopping, and
    managing a packet capture session. It runs Scapy's ``sniff()`` in
    a background thread and delivers packets to registered callbacks.

    Example:
        >>> from sniffer.core.capture import PacketCapture
        >>> capture = PacketCapture(interface="Wi-Fi")
        >>> capture.add_callback(lambda pkt, data: print(data))
        >>> capture.start()
        >>> # ... packets are captured in the background ...
        >>> capture.stop()
        >>> print(f"Captured {capture.stats.packets_captured} packets")

    Args:
        interface: The network interface to capture on.
        bpf_filter: An optional BPF filter expression.
        packet_count: Max packets to capture (0 = unlimited).
        timeout: Capture timeout in seconds (0 = no timeout).
        buffer_size: Maximum number of packets to keep in memory.
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "",
        packet_count: int = 0,
        timeout: int = 0,
        buffer_size: int = 10000,
    ) -> None:
        """Initialize the capture engine.

        Args:
            interface: Network interface name to capture on.
            bpf_filter: BPF filter expression (empty = capture all).
            packet_count: Max packets (0 = unlimited).
            timeout: Timeout in seconds (0 = no timeout).
            buffer_size: Max packets to keep in the buffer.
        """
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._packet_count = packet_count
        self._timeout = timeout

        # Thread-safe packet buffer with max size
        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self._buffer_lock = threading.Lock()

        # Raw Scapy packets (for PCAP export)
        self._raw_packets: deque[Any] = deque(maxlen=buffer_size)

        # Callback pipeline — functions called for each captured packet
        self._callbacks: list[PacketCallback] = []

        # Threading controls
        self._stop_event = threading.Event()
        self._capture_thread: threading.Thread | None = None

        # Live statistics
        self.stats = CaptureStats()

        # Packet counter (for sequential numbering)
        self._packet_number = 0

        logger.info(
            "PacketCapture initialized: interface=%s, filter='%s', "
            "count=%d, timeout=%d, buffer=%d",
            interface,
            bpf_filter or "(none)",
            packet_count,
            timeout,
            buffer_size,
        )

    def add_callback(self, callback: PacketCallback) -> None:
        """Register a callback to be called for each captured packet.

        Callbacks receive two arguments:
        1. The raw Scapy packet object.
        2. The parsed packet data dictionary.

        Callbacks are called in the capture thread, so they should be
        fast and non-blocking. Heavy processing should be offloaded.

        Args:
            callback: A function with signature ``(packet, data) -> None``.
        """
        self._callbacks.append(callback)
        logger.debug("Registered packet callback: %s", callback.__name__)

    def start(self) -> None:
        """Start capturing packets in a background thread.

        This method returns immediately. Packets are delivered to
        registered callbacks as they arrive.

        Raises:
            CaptureError: If capture is already running or fails to start.
        """
        if self._capture_thread and self._capture_thread.is_alive():
            raise CaptureError("Capture is already running")

        # Pre-capture verification: Ensure Scapy can access this interface
        # This prevents silent failures in the background thread.
        try:
            from scapy.all import get_if_hwaddr

            # Try to get the hardware address (MAC) of the interface.
            # This is a fast, non-blocking way to check if Scapy recognizes the interface
            # and has the necessary permissions/drivers to access it.
            # On loopback interfaces on some systems, this might fail, so we catch it
            # and try a mock sniff instead if needed.
            try:
                mac = get_if_hwaddr(self._interface)
                logger.debug(
                    "Successfully verified access to interface '%s' (MAC: %s)",
                    self._interface,
                    mac,
                )
            except Exception:
                # Fallback verification: quick sniff
                import scapy.all as scapy

                scapy.sniff(iface=self._interface, count=0, timeout=0.1)
                logger.debug(
                    "Successfully verified access to interface '%s' via sniff",
                    self._interface,
                )
        except Exception as exc:
            logger.error("Interface access verification failed: %s", exc)
            raise CaptureError(
                f"Cannot access interface '{self._interface}'. Scapy failed to bind to it.",
                details=f"Ensure you are running as Administrator/root and Npcap/WinPcap is installed. Details: {exc}",
            ) from exc

        self._stop_event.clear()
        self.stats = CaptureStats(start_time=time.time())
        self._packet_number = 0

        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            name="PacketCaptureThread",
            daemon=True,  # Thread dies when main thread exits
        )
        self._capture_thread.start()
        logger.info("Packet capture started on '%s'", self._interface)

    def stop(self) -> CaptureStats:
        """Stop the capture session and return final statistics.

        Signals the capture thread to stop and waits for it to finish.
        This method is safe to call multiple times.

        Returns:
            The final ``CaptureStats`` for the session.
        """
        if not self._capture_thread or not self._capture_thread.is_alive():
            logger.debug("Capture is not running — nothing to stop")
            return self.stats

        logger.info("Stopping packet capture...")
        self._stop_event.set()

        # Wait for the capture thread to finish (with timeout)
        self._capture_thread.join(timeout=5.0)
        if self._capture_thread.is_alive():
            logger.warning("Capture thread did not stop within 5 seconds")

        self.stats.end_time = time.time()
        logger.info(
            "Capture stopped. %d packets captured in %.1f seconds (%.1f pkt/s)",
            self.stats.packets_captured,
            self.stats.duration,
            self.stats.packets_per_second,
        )
        return self.stats

    @property
    def is_running(self) -> bool:
        """Check if the capture session is currently active."""
        return (
            self._capture_thread is not None
            and self._capture_thread.is_alive()
            and not self._stop_event.is_set()
        )

    def get_packets(self) -> list[dict[str, Any]]:
        """Return a copy of all captured packets (parsed data).

        Thread-safe — acquires the buffer lock during copy.

        Returns:
            A list of parsed packet dictionaries.
        """
        with self._buffer_lock:
            return list(self._buffer)

    def get_raw_packets(self) -> list[Any]:
        """Return raw Scapy packet objects for PCAP export.

        Returns:
            A list of raw Scapy packet objects.
        """
        return list(self._raw_packets)

    def _capture_loop(self) -> None:
        """Run the Scapy sniff loop (executes in background thread).

        This method is the target of the capture thread. It calls
        Scapy's ``sniff()`` with our configuration and handles all
        errors that may occur during capture.
        """
        try:
            from scapy.all import sniff

            logger.debug("Starting Scapy sniff() on '%s'...", self._interface)

            # Build sniff kwargs
            sniff_kwargs: dict[str, Any] = {
                "iface": self._interface,
                "prn": self._packet_handler,
                "store": False,  # We handle storage ourselves
                "stop_filter": lambda _pkt: self._stop_event.is_set(),
            }

            # Optional BPF filter
            if self._bpf_filter:
                sniff_kwargs["filter"] = self._bpf_filter

            # Optional packet count limit
            if self._packet_count > 0:
                sniff_kwargs["count"] = self._packet_count

            # Optional timeout
            if self._timeout > 0:
                sniff_kwargs["timeout"] = self._timeout

            # Run the capture — this blocks until stopped
            sniff(**sniff_kwargs)

        except KeyboardInterrupt:
            logger.info("Capture interrupted by user (Ctrl+C)")
        except ImportError as exc:
            logger.critical("Scapy is not installed: %s", exc)
            raise CaptureError(
                "Scapy is not installed",
                details="Install with: pip install scapy",
            ) from exc
        except PermissionError as exc:
            logger.critical("Permission denied for packet capture: %s", exc)
            raise CaptureError(
                "Permission denied for packet capture",
                details="Run as Administrator (Windows) or with sudo (Linux/macOS).",
            ) from exc
        except OSError as exc:
            logger.error("OS error during capture: %s", exc)
            raise CaptureError(
                "Capture failed due to OS error",
                details=str(exc),
            ) from exc
        except Exception as exc:
            logger.error("Unexpected error during capture: %s", exc, exc_info=True)
            raise CaptureError(
                "Unexpected capture error",
                details=str(exc),
            ) from exc
        finally:
            self.stats.end_time = time.time()
            logger.debug("Capture loop exited")

    def _packet_handler(self, raw_packet: Any) -> None:
        """Process a single captured packet (called by Scapy for each packet).

        This is the callback passed to ``scapy.sniff(prn=...)``. It:
        1. Increments counters and protocol statistics.
        2. Parses the packet through the parser pipeline.
        3. Stores the result in the buffer.
        4. Calls all registered callbacks.
        5. Logs the packet summary at DEBUG level.

        Args:
            raw_packet: A raw Scapy packet object.
        """
        try:
            self._packet_number += 1
            packet_size = len(raw_packet)

            # Update basic statistics
            self.stats.packets_captured += 1
            self.stats.bytes_captured += packet_size

            # Parse the packet through the parser pipeline
            parsed_data = self._parse_packet(raw_packet)

            # Update per-protocol and per-IP statistics
            layers = parsed_data.get("layers", [])
            ip_data = parsed_data.get("ip", {})
            src_ip = ip_data.get("src_ip", "")
            dst_ip = ip_data.get("dst_ip", "")
            self.stats.record_packet(layers, packet_size, src_ip, dst_ip)

            # Store raw packet (for PCAP export) and parsed data
            self._raw_packets.append(raw_packet)
            with self._buffer_lock:
                self._buffer.append(parsed_data)

            # Notify all registered callbacks
            for callback in self._callbacks:
                try:
                    callback(raw_packet, parsed_data)
                except Exception as cb_exc:
                    logger.warning(
                        "Callback '%s' failed on packet #%d: %s",
                        callback.__name__,
                        self._packet_number,
                        cb_exc,
                    )

            # Log every packet summary at DEBUG level (written to log file)
            logger.debug(
                "Packet #%d: %s → %s [%s] %d bytes",
                self._packet_number,
                src_ip or "?",
                dst_ip or "?",
                " / ".join(layers) if layers else "Unknown",
                packet_size,
            )

            # Log milestone packets at INFO level
            if self.stats.packets_captured % 1000 == 0:
                logger.info(
                    "Milestone: %d packets captured (%d bytes, %.1f pkt/s)",
                    self.stats.packets_captured,
                    self.stats.bytes_captured,
                    self.stats.instantaneous_rate,
                )

        except Exception as exc:
            self.stats.packets_dropped += 1
            logger.warning(
                "Failed to process packet #%d: %s",
                self._packet_number,
                exc,
            )

    def _parse_packet(self, raw_packet: Any) -> dict[str, Any]:
        """Parse a raw Scapy packet into a structured dictionary.

        Walks through the packet's protocol layers and extracts
        relevant fields using the parser pipeline.

        Args:
            raw_packet: A raw Scapy packet object.

        Returns:
            A dictionary with parsed packet data.
        """
        from sniffer.parsers import parse_packet

        parsed = parse_packet(raw_packet, self._packet_number)
        return parsed
