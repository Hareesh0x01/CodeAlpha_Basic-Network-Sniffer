"""
HTTP Message Parser (Basic)
============================

Performs basic HTTP parsing by inspecting the Raw payload layer for
HTTP request/response patterns. This is a heuristic parser — modern
HTTPS traffic is encrypted and cannot be parsed without TLS decryption.

"""

from __future__ import annotations

import re
from typing import Any

from sniffer.parsers.base import BaseParser

# HTTP methods recognized by this parser
HTTP_METHODS = frozenset(
    {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "CONNECT",
        "TRACE",
    }
)

# Regex to match HTTP request line: METHOD /path HTTP/1.x
HTTP_REQUEST_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)"
    rb"\s+(\S+)\s+HTTP/(\d\.\d)",
    re.IGNORECASE,
)

# Regex to match HTTP response status line: HTTP/1.x 200 OK
HTTP_RESPONSE_RE = re.compile(
    rb"^HTTP/(\d\.\d)\s+(\d{3})\s+(.*)",
    re.IGNORECASE,
)


class HTTPParser(BaseParser):
    """Parses basic plaintext HTTP requests and responses.

    Extracts:
        - ``is_request``: Whether this is a request or response.
        - ``method``: HTTP method (GET, POST, etc.) — requests only.
        - ``url``: Request URL/path — requests only.
        - ``http_version``: HTTP version (e.g., "1.1").
        - ``status_code``: HTTP status code — responses only.
        - ``status_text``: HTTP status text — responses only.
        - ``host``: Host header value (if present).
        - ``content_type``: Content-Type header value (if present).
        - ``content_length``: Content-Length header value (if present).

    Note:
        HTTPS (encrypted) traffic will NOT be parsed. Only plaintext
        HTTP on ports like 80 and 8080 is supported.
    """

    @property
    def layer_name(self) -> str:
        return "HTTP"

    def can_parse(self, packet: Any) -> bool:
        """Check if the packet contains HTTP data in its Raw layer.

        First checks for Scapy's built-in HTTP layer (if scapy[http]
        is installed), then falls back to heuristic Raw layer inspection.
        """
        # Try Scapy's built-in HTTP layer first
        try:
            from scapy.layers.http import HTTP

            if packet.haslayer(HTTP):
                return True
        except ImportError:
            pass

        # Fall back to Raw layer heuristic
        from scapy.packet import Raw

        if not packet.haslayer(Raw):
            return False

        payload = bytes(packet[Raw].load[:20])  # Check first 20 bytes
        return bool(HTTP_REQUEST_RE.match(payload) or HTTP_RESPONSE_RE.match(payload))

    def parse(self, packet: Any) -> dict[str, Any]:
        """Extract HTTP message fields.

        Args:
            packet: A Scapy packet containing HTTP data.

        Returns:
            Dictionary with HTTP fields.

        Example output (request)::

            {
                "is_request": True,
                "method": "GET",
                "url": "/index.html",
                "http_version": "1.1",
                "host": "example.com",
                "content_type": "",
                "content_length": 0
            }
        """
        # Try Scapy's HTTP layer first
        try:
            from scapy.layers.http import HTTPRequest, HTTPResponse

            if packet.haslayer(HTTPRequest):
                return self._parse_scapy_request(packet[HTTPRequest])
            if packet.haslayer(HTTPResponse):
                return self._parse_scapy_response(packet[HTTPResponse])
        except ImportError:
            pass

        # Fall back to raw payload parsing
        return self._parse_raw_payload(packet)

    @staticmethod
    def _parse_scapy_request(http_req: Any) -> dict[str, Any]:
        """Parse using Scapy's built-in HTTPRequest layer."""

        def decode(val: Any) -> str:
            if isinstance(val, bytes):
                return val.decode("utf-8", errors="replace")
            return str(val) if val else ""

        return {
            "is_request": True,
            "method": decode(http_req.Method),
            "url": decode(http_req.Path),
            "http_version": decode(http_req.Http_Version),
            "host": decode(getattr(http_req, "Host", b"")),
            "content_type": decode(getattr(http_req, "Content_Type", b"")),
            "content_length": int(getattr(http_req, "Content_Length", 0) or 0),
        }

    @staticmethod
    def _parse_scapy_response(http_resp: Any) -> dict[str, Any]:
        """Parse using Scapy's built-in HTTPResponse layer."""

        def decode(val: Any) -> str:
            if isinstance(val, bytes):
                return val.decode("utf-8", errors="replace")
            return str(val) if val else ""

        status_code_raw = getattr(http_resp, "Status_Code", b"0")
        try:
            status_code = int(status_code_raw)
        except (ValueError, TypeError):
            status_code = 0

        return {
            "is_request": False,
            "status_code": status_code,
            "status_text": decode(getattr(http_resp, "Reason_Phrase", b"")),
            "http_version": decode(http_resp.Http_Version),
            "content_type": decode(getattr(http_resp, "Content_Type", b"")),
            "content_length": int(getattr(http_resp, "Content_Length", 0) or 0),
        }

    def _parse_raw_payload(self, packet: Any) -> dict[str, Any]:
        """Parse HTTP from the Raw payload using regex heuristics."""
        from scapy.packet import Raw

        payload = bytes(packet[Raw].load)

        # Try to match HTTP request
        req_match = HTTP_REQUEST_RE.match(payload)
        if req_match:
            method = req_match.group(1).decode("ascii")
            url = req_match.group(2).decode("ascii", errors="replace")
            version = req_match.group(3).decode("ascii")

            return {
                "is_request": True,
                "method": method,
                "url": url,
                "http_version": version,
                "host": self._extract_header(payload, b"Host"),
                "content_type": self._extract_header(payload, b"Content-Type"),
                "content_length": int(
                    self._extract_header(payload, b"Content-Length") or 0
                ),
            }

        # Try to match HTTP response
        resp_match = HTTP_RESPONSE_RE.match(payload)
        if resp_match:
            version = resp_match.group(1).decode("ascii")
            status_code = int(resp_match.group(2))
            status_text = resp_match.group(3).decode("ascii", errors="replace").strip()

            return {
                "is_request": False,
                "status_code": status_code,
                "status_text": status_text,
                "http_version": version,
                "content_type": self._extract_header(payload, b"Content-Type"),
                "content_length": int(
                    self._extract_header(payload, b"Content-Length") or 0
                ),
            }

        return {"is_request": False, "raw": "Unparseable HTTP data"}

    @staticmethod
    def _extract_header(payload: bytes, header_name: bytes) -> str:
        """Extract a single HTTP header value from raw bytes.

        Args:
            payload: The raw HTTP payload bytes.
            header_name: The header name to search for (e.g., b"Host").

        Returns:
            The header value as a string, or empty string if not found.
        """
        pattern = re.compile(
            header_name + rb":\s*(.+?)(?:\r\n|\r|\n)",
            re.IGNORECASE,
        )
        match = pattern.search(payload)
        if match:
            return match.group(1).decode("ascii", errors="replace").strip()
        return ""
