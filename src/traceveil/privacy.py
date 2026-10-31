"""Actionable pre-sharing review; no original values enter the returned report."""

from collections import Counter

from .core import inspect_har, sanitize


def privacy_review(document):
    """Separate removable exposure surfaces from risks retained in the export.

    The existing inspector inventories removable fields. This workflow adds a
    sharing decision, category summaries, and a checklist for residual risks.
    Neither canonical verification nor this review certifies anonymity.
    """
    inventory = inspect_har(document)
    entries = sanitize(document)["log"]["entries"]
    surfaces = Counter(item["category"] for item in inventory["findings"])
    counts = {
        "timing_fingerprint": sum(e["time"] > 0 or any(v > 0 for v in e["timings"].values())
                                  for e in entries),
        "relative_timeline": sum(e["startedDateTime"] != "2000-01-01T00:00:00Z"
                                 for e in entries),
        "size_fingerprint": sum(e["response"]["content"]["size"] > 0 or
                                e["response"]["bodySize"] > 0 for e in entries),
        "activity_pattern": len(entries),
    }
    guidance = {
        "timing_fingerprint": "Request durations and timing phases remain. Share only if this precision is necessary.",
        "relative_timeline": "Relative request spacing remains. It can reveal a workflow even though original dates are removed.",
        "size_fingerprint": "Response sizes remain. Distinctive sizes can identify resources or user activity.",
        "activity_pattern": "Order, endpoint relationships, methods, status codes and MIME types remain. Compare with what a recipient already knows.",
    }
    canonical = inventory["canonical_safe_format"]
    return {
        "format": "traceveil-privacy-review-1",
        "entries": len(entries),
        "canonical_safe_format": canonical,
        "next_step": "manual_review" if canonical else "sanitize_first",
        "removable_surfaces": dict(sorted(surfaces.items())),
        "residual_risks": [{"code": code, "affected_entries": count,
                            "guidance": guidance[code]}
                           for code, count in counts.items() if count],
        "checklist": [
            "Sanitize the original capture; do not share it alongside the export.",
            "Decide whether retained timing, sizes and relationships disclose too much for this recipient.",
            "Check filenames, surrounding screenshots and accompanying messages for separate disclosures.",
        ],
        "notice": "This report omits original values. It cannot certify anonymity or detect every disclosure. A canonical archive still needs manual review.",
    }
