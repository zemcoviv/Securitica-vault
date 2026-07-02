"""Optional local GeoLite2 lookup for notification metadata (BRIEF §6.2:
"IP/гео из локальной GeoLite2").

We do not ship a GeoLite2 database (MaxMind's license requires a direct
account signup) or the `geoip2` dependency by default — this stays a no-op
until an operator opts in. Set GEOIP_DB_PATH to a local GeoLite2-City.mmdb
file and install `geoip2` to enable it; everything degrades gracefully
without either.
"""

from __future__ import annotations

import os

_DB_PATH = os.environ.get("GEOIP_DB_PATH", "")
_reader = None
_init_attempted = False


def _get_reader():
    global _reader, _init_attempted
    if _init_attempted:
        return _reader
    _init_attempted = True
    if not _DB_PATH:
        return None
    try:
        import geoip2.database  # type: ignore[import-not-found]

        _reader = geoip2.database.Reader(_DB_PATH)
    except Exception:
        _reader = None
    return _reader


def lookup_geo(ip: str) -> str | None:
    """Best-effort "City, Country" string, or None if unavailable."""
    reader = _get_reader()
    if reader is None:
        return None
    try:
        response = reader.city(ip)
        parts = [p for p in (response.city.name, response.country.name) if p]
        return ", ".join(parts) if parts else None
    except Exception:
        return None
