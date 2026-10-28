import logging
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


def _origin(url):
    if not isinstance(url, str) or not url or any(char.isspace() for char in url) or "\\" in url:
        raise ValueError("URL must be an absolute HTTP(S) URL")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("URL must be an absolute HTTP(S) URL") from error

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("URL must be an absolute HTTP(S) URL")

    hostname = hostname.rstrip(".").lower()
    if not hostname:
        raise ValueError("URL must be an absolute HTTP(S) URL")
    if ":" in hostname:
        hostname = f"[{hostname}]"

    scheme = parsed.scheme.lower()
    if port == (443 if scheme == "https" else 80):
        port = None
    authority = hostname if port is None else f"{hostname}:{port}"
    return f"{scheme}://{authority}"


def validate_url(url, allowed_origins):
    """Require an absolute HTTP(S) URL whose origin is explicitly allowed."""
    origin = _origin(url)
    allowed = {_origin(allowed_origin) for allowed_origin in allowed_origins}
    if origin not in allowed:
        logger.warning("Rejected URL with unapproved origin: %s", origin)
        raise ValueError("URL origin is not allowed")
    return url
