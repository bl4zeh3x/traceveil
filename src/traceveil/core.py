"""Build a new HAR from a small allowlist; never copy unknown fields."""

from datetime import datetime, timedelta, timezone
import math
from urllib.parse import urlsplit

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
MIMES = {"text/html", "text/css", "text/plain", "text/javascript", "application/javascript",
         "application/json", "application/xml", "image/png", "image/jpeg", "image/gif",
         "image/webp", "image/svg+xml", "font/woff", "font/woff2", "application/octet-stream"}
EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


def _entries(document):
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise ValueError("Expected an object containing log.entries")
    entries = document["log"].get("entries")
    if not isinstance(entries, list):
        raise ValueError("Expected log.entries to be a list")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            raise ValueError(f"Entry {index}: expected a request object")
        if not isinstance(entry.get("response"), dict):
            raise ValueError(f"Entry {index}: expected a response object")
    return entries


def _number(value, default=0):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    try:
        return value if math.isfinite(value) and 0 <= value <= 1_000_000_000 else default
    except OverflowError:
        return default


def _integer(value, default=0):
    return int(_number(value, default))


def _timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except (ValueError, OverflowError):
        return None


def sanitize(document):
    """Remove payloads and identifiers while retaining timing and request relationships.

    Origin and route labels are stable only within one archive. Absolute dates,
    headers, cookies, query values, response text, custom metadata and page titles
    are deliberately discarded. This is not general-purpose anonymization.
    """
    entries = _entries(document)
    hosts, routes = {}, {}
    dates = [_timestamp(e.get("startedDateTime")) for e in entries]
    baseline = next((date for date in dates if date is not None), EPOCH)
    clean = []
    for index, entry in enumerate(entries):
        request, response = entry["request"], entry["response"]
        raw_url = request.get("url")
        try:
            if not isinstance(raw_url, str) or len(raw_url) > 100_000:
                raise ValueError
            parts = urlsplit(raw_url)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise ValueError
            # Parse port too, so invalid ports fail without echoing the URL.
            origin = (parts.scheme, parts.hostname, parts.port)
        except (ValueError, TypeError):
            raise ValueError(f"Entry {index}: expected a valid HTTP(S) URL") from None
        host = hosts.setdefault(origin, len(hosts) + 1)
        route = routes.setdefault((origin, parts.path), len(routes) + 1)
        method = request.get("method")
        status = _integer(response.get("status"))
        if not 100 <= status <= 599:
            status = 0
        content = response.get("content")
        content = content if isinstance(content, dict) else {}
        mime = content.get("mimeType", "")
        mime = mime.split(";", 1)[0].lower().strip() if isinstance(mime, str) else ""
        mime = mime if mime in MIMES else "application/octet-stream"
        raw_timings = entry.get("timings")
        raw_timings = raw_timings if isinstance(raw_timings, dict) else {}
        timings = {key: _number(raw_timings.get(key), -1) for key in
                   ("blocked", "dns", "connect", "send", "wait", "receive", "ssl")}
        elapsed = (dates[index] - baseline).total_seconds() if dates[index] else 0
        # Cap extreme offsets; large/untrusted dates must not overflow report rendering.
        elapsed = min(max(elapsed, 0), 31_536_000)
        start = (EPOCH + timedelta(seconds=elapsed)).isoformat().replace("+00:00", "Z")
        clean.append({
            "startedDateTime": start,
            "time": _number(entry.get("time")),
            "request": {"method": method if isinstance(method, str) and method in METHODS else "OTHER",
                        "url": f"https://host-{host}.invalid/route-{route}",
                        "httpVersion": "HTTP/1.1", "headers": [], "cookies": [],
                        "queryString": [], "headersSize": -1, "bodySize": -1},
            "response": {"status": status, "statusText": "", "httpVersion": "HTTP/1.1",
                         "headers": [], "cookies": [],
                         "content": {"size": _integer(content.get("size")), "mimeType": mime},
                         "redirectURL": "", "headersSize": -1,
                         "bodySize": _integer(response.get("bodySize"), -1)},
            "cache": {}, "timings": timings,
        })
    return {"log": {"version": "1.2", "creator": {"name": "Traceveil", "version": "0.1.0"},
                    "entries": clean}}


def inspect_har(document):
    """Return counts and entry indices, never copies of potentially sensitive values."""
    entries = _entries(document)
    findings = []
    for index, entry in enumerate(entries):
        request, response = entry["request"], entry["response"]
        for side, data in (("request", request), ("response", response)):
            for key in ("headers", "cookies"):
                if data.get(key):
                    findings.append({"entry": index, "category": f"{side}.{key}"})
        if request.get("queryString") or "?" in str(request.get("url", "")):
            findings.append({"entry": index, "category": "request.query"})
        if request.get("postData"):
            findings.append({"entry": index, "category": "request.body"})
        if isinstance(response.get("content"), dict) and response["content"].get("text"):
            findings.append({"entry": index, "category": "response.body"})
    safe = sanitize(document)
    return {"entries": len(entries), "findings": findings,
            "canonical_safe_format": document == safe,
            "notice": "Counts are review aids, not a guarantee that an arbitrary archive is safe."}


def is_sanitized(document):
    """Accept only the exact conservative output schema and pseudonymization."""
    return document == sanitize(document)
