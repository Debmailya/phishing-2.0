import ipaddress
from urllib.parse import urlparse

from fastapi import HTTPException


def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Unsupported URL scheme")

    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=400, detail="Invalid URL host")

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise HTTPException(status_code=400, detail="SSRF-protected host blocked")
    except ValueError:
        blocked_suffixes = (".internal", ".local", ".corp")
        if host.endswith(blocked_suffixes) or host in {"localhost"}:
            raise HTTPException(status_code=400, detail="SSRF-protected host blocked")
