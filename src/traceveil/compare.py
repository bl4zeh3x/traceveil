"""Compare canonical captures using only allowlisted aggregate metrics."""

from collections import Counter
import math
from statistics import median

from .core import is_sanitized


def _summary(document):
    if not is_sanitized(document):
        raise ValueError("Comparison requires canonical conservative captures")
    entries = document["log"]["entries"]
    durations = sorted(e["time"] for e in entries)
    status = Counter("unknown" if e["response"]["status"] == 0 else
                     f'{e["response"]["status"] // 100}xx' for e in entries)
    methods = Counter(e["request"]["method"] for e in entries)
    sizes = [e["response"]["bodySize"] for e in entries]
    return {
        "requests": len(entries),
        "total_request_ms": sum(durations),
        "median_request_ms": median(durations) if durations else 0,
        "p95_request_ms": durations[math.ceil(len(durations) * .95) - 1] if durations else 0,
        "known_response_bytes": sum(size for size in sizes if size >= 0),
        "unknown_response_sizes": sum(size < 0 for size in sizes),
        "error_responses": sum(e["response"]["status"] >= 400 for e in entries),
        "methods": dict(sorted(methods.items())),
        "status_classes": dict(sorted(status.items())),
    }


def compare_captures(before, after):
    """Return no endpoint labels, raw timestamps, filenames or inferred identities.

    Host/route labels are local to each capture, so they are deliberately never
    matched. Aggregate metrics may still fingerprint activity; review the result.
    """
    left, right = _summary(before), _summary(after)
    changes = {}
    for key in left:
        if isinstance(left[key], dict):
            changes[key] = {k: right[key].get(k, 0) - left[key].get(k, 0)
                            for k in sorted(left[key].keys() | right[key].keys())}
        else:
            changes[key] = {"delta": right[key] - left[key],
                            "percent": 100 * (right[key] - left[key]) / left[key] if left[key] else None}
    return {"format": "traceveil-comparison-1", "before": left, "after": right,
            "changes": changes,
            "notice": "Aggregate metrics only; endpoint identities are neither matched nor inferred. Totals can still fingerprint activity. Review before sharing."}
