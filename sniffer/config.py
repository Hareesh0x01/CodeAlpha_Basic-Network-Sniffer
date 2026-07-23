"""
Configuration Management
==========================

Provides a centralized, immutable configuration object for the application.
Settings are resolved in priority order: CLI args > environment vars > defaults.

"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SnifferConfig:
    """Immutable configuration for the Basic Network Sniffer.

    Attributes:
        interface: Network interface to capture on (None = prompt user).
        bpf_filter: BPF filter expression (empty = capture everything).
        packet_count: Max packets to capture (0 = unlimited).
        timeout: Capture timeout in seconds (0 = no timeout).
        output_dir: Directory for exported files.
        log_dir: Directory for log files.
        verbose: Enable INFO-level console logging.
        debug: Enable DEBUG-level console logging.
        no_color: Disable colored terminal output.
        export_format: Default export format ('csv', 'json', 'pcap', or None).
    """

    # ─── Capture Settings ───────────────────────────────────────────────
    interface: str | None = None
    bpf_filter: str = ""
    packet_count: int = 0  # 0 = unlimited
    timeout: int = 0  # 0 = no timeout

    # ─── Output Settings ────────────────────────────────────────────────
    output_dir: Path = field(default_factory=lambda: Path("output"))
    log_dir: Path = field(default_factory=lambda: Path("logs"))
    export_format: str | None = None

    # ─── Display Settings ───────────────────────────────────────────────
    verbose: bool = False
    debug: bool = False
    no_color: bool = False

    @classmethod
    def from_env(cls, **cli_overrides: object) -> SnifferConfig:
        """Create a config by merging CLI arguments with environment variables.

        Priority: CLI args > environment variables > TOML config > defaults.

        Environment variables (all optional):
            - ``SNIFFER_INTERFACE``: Default interface name.
            - ``SNIFFER_FILTER``: Default BPF filter.
            - ``SNIFFER_PACKET_COUNT``: Default packet count limit.
            - ``SNIFFER_TIMEOUT``: Default capture timeout.
            - ``SNIFFER_OUTPUT_DIR``: Default output directory.
            - ``SNIFFER_LOG_DIR``: Default log directory.
            - ``SNIFFER_NO_COLOR``: Disable colors (any non-empty value).

        TOML Configuration:
            Loads from ``sniffer.toml`` in the current directory if present.

        Args:
            **cli_overrides: Keyword arguments from CLI argument parser.
                Only non-None values override environment/defaults.

        Returns:
            A frozen ``SnifferConfig`` instance.

        Example:
            >>> config = SnifferConfig.from_env(interface="eth0", verbose=True)
            >>> config.interface
            'eth0'
        """
        # Start with defaults, then load TOML, then ENV, then CLI overrides.
        env_values: dict[str, object] = {}

        # 1. Load TOML configuration if it exists
        toml_path = Path("sniffer.toml")
        if toml_path.exists():
            try:
                with open(toml_path, "rb") as f:
                    toml_data = tomllib.load(f)
                    # Support flat config or nested [sniffer] table
                    config_data = toml_data.get("sniffer", toml_data)

                    if "interface" in config_data:
                        env_values["interface"] = str(config_data["interface"])
                    if "filter" in config_data:
                        env_values["bpf_filter"] = str(config_data["filter"])
                    if "packet_count" in config_data:
                        env_values["packet_count"] = int(config_data["packet_count"])
                    if "timeout" in config_data:
                        env_values["timeout"] = int(config_data["timeout"])
                    if "output_dir" in config_data:
                        env_values["output_dir"] = Path(config_data["output_dir"])
                    if "log_dir" in config_data:
                        env_values["log_dir"] = Path(config_data["log_dir"])
                    if "no_color" in config_data:
                        env_values["no_color"] = bool(config_data["no_color"])
            except Exception as e:
                # We don't have logger configured yet, so just print a warning
                print(f"Warning: Failed to parse sniffer.toml: {e}")

        # 2. Environment variables override TOML

        # String settings
        env_interface = os.environ.get("SNIFFER_INTERFACE")
        if env_interface:
            env_values["interface"] = env_interface

        env_filter = os.environ.get("SNIFFER_FILTER")
        if env_filter:
            env_values["bpf_filter"] = env_filter

        # Integer settings
        env_count = os.environ.get("SNIFFER_PACKET_COUNT")
        if env_count and env_count.isdigit():
            env_values["packet_count"] = int(env_count)

        env_timeout = os.environ.get("SNIFFER_TIMEOUT")
        if env_timeout and env_timeout.isdigit():
            env_values["timeout"] = int(env_timeout)

        # Path settings
        env_output = os.environ.get("SNIFFER_OUTPUT_DIR")
        if env_output:
            env_values["output_dir"] = Path(env_output)

        env_log_dir = os.environ.get("SNIFFER_LOG_DIR")
        if env_log_dir:
            env_values["log_dir"] = Path(env_log_dir)

        # Boolean settings
        env_no_color = os.environ.get("SNIFFER_NO_COLOR")
        if env_no_color:
            env_values["no_color"] = True

        # CLI overrides take highest priority (skip None values)
        for key, value in cli_overrides.items():
            if value is not None:
                env_values[key] = value

        return cls(**env_values)  # type: ignore[arg-type]

    def get_console_log_level(self) -> int:
        """Determine the console log level based on verbosity flags.

        Returns:
            A ``logging`` level constant:
            - ``DEBUG`` (10) if ``self.debug`` is True
            - ``INFO`` (20) if ``self.verbose`` is True
            - ``WARNING`` (30) otherwise
        """
        import logging

        if self.debug:
            return logging.DEBUG
        if self.verbose:
            return logging.INFO
        return logging.WARNING
