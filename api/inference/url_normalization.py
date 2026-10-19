"""URL normalization helpers for production host-only ML inference."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_host_inference_url(url: str) -> str:
    """Return ``scheme://host[:non-default-port]`` or raise ``ValueError``.

    Path, query, and fragment are intentionally removed before ML feature
    extraction. Keep the submitted URL separately for assessment evidence.
    """
    if not isinstance(url, str) or not url:
        raise ValueError("URL must be a non-empty string.")
    if url != url.strip() or any(char.isspace() or ord(char) < 32 for char in url):
        raise ValueError("URL must not contain whitespace or control characters.")

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must contain a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing user information are not supported.")
        port = parsed.port
    except ValueError as exc:
        if str(exc) in {
            "Only HTTP and HTTPS URLs are supported.",
            "URL must contain a hostname.",
            "URLs containing user information are not supported.",
        }:
            raise
        raise ValueError("URL authority or port is malformed.") from exc

    host = parsed.hostname.rstrip(".").lower()
    if not host:
        raise ValueError("URL must contain a hostname.")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if ":" in host or "%" in host:
            raise ValueError("IPv6 zone identifiers and malformed IP literals are not supported.")
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Hostname is not a valid internationalized domain name.") from exc
        labels = ascii_host.split(".")
        if len(ascii_host) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
            raise ValueError("Hostname is malformed.")
        authority = ascii_host
    else:
        normalized_ip = address.compressed.lower()
        authority = f"[{normalized_ip}]" if address.version == 6 else normalized_ip

    default_port = 80 if scheme == "http" else 443
    if port is not None and port != default_port:
        authority += f":{port}"
    return f"{scheme}://{authority}"
