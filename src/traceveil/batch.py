"""Isolated batch exports without input names or original values in the manifest."""

import hashlib
import json
from pathlib import Path

from .core import sanitize
from .storage import load, write_new


def sanitize_batch(inputs, output):
    """Use a new private directory; output IDs correspond to input argument order.

    Existing destinations are refused, even empty directories. Individual invalid
    captures do not stop other captures. A completed manifest is written last.
    """
    inputs = list(inputs)
    if not 1 <= len(inputs) <= 1000:
        raise ValueError("A batch needs between 1 and 1000 inputs")
    output = Path(output)
    output.mkdir(mode=0o700)
    results = []
    for index, source in enumerate(inputs, 1):
        item = {"input_id": index}
        try:
            clean = sanitize(load(Path(source)))
            text = json.dumps(clean, indent=2, allow_nan=False) + "\n"
            name = f"capture-{index:04d}.har"
            write_new(output / name, text)
            item.update(status="written", output=name,
                        entries=len(clean["log"]["entries"]),
                        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest())
        except (OSError, ValueError, TypeError, RecursionError):
            item.update(status="failed", reason="Input rejected or output unavailable")
        results.append(item)
    failed = sum(item["status"] == "failed" for item in results)
    manifest = {"format": "traceveil-batch-1", "succeeded": len(results) - failed,
                "failed": failed, "files": results,
                "notice": "Input IDs follow argument order. Input names are omitted. Review outputs before sharing."}
    write_new(output / "manifest.json", json.dumps(manifest, indent=2, allow_nan=False) + "\n")
    return manifest
