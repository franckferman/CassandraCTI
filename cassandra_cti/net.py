# net.py - shared HTTP/TLS helpers
"""Central network helpers so every fetch is consistently:
  - TLS-verified by default (sends SNI; opt out with CTI_TLS_NO_VERIFY=1 for
    intercepting corporate proxies), and
  - size-bounded (a malicious/MITM'd feed cannot exhaust memory).
"""
from __future__ import annotations
import os
import ssl
from urllib.parse import urlparse

# Hard cap on any single HTTP response body we buffer (25 MiB).
MAX_BYTES = 25 * 1024 * 1024


def ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if os.environ.get("CTI_TLS_NO_VERIFY") == "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def read_capped(resp, max_bytes: int = MAX_BYTES) -> bytes:
    """Read a response body, refusing to buffer more than `max_bytes`."""
    buf = bytearray()
    async for chunk in resp.content.iter_chunked(65536):
        buf += chunk
        if len(buf) > max_bytes:
            raise RuntimeError(f"response body exceeds {max_bytes}B cap ({resp.url})")
    return bytes(buf)


def valid_http_url(url) -> bool:
    """True only for a well-formed http(s) URL with a dotted host. Discord
    embed.url and Teams OpenUri return HTTP 400 on a malformed URL, which would
    drop the whole message — callers should omit the link when this is False."""
    try:
        p = urlparse(url or "")
    except Exception:
        return False
    return p.scheme in ("http", "https") and "." in p.netloc
