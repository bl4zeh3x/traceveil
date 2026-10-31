"""Run all new workflows against synthetic captures using the installed CLI."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def run(*args, expected=0):
    result = subprocess.run([sys.executable, "-m", "traceveil", *map(str, args)],
                            capture_output=True, text=True)
    if result.returncode != expected:
        raise SystemExit("Demo command failed. Check installation and use a new output directory.")
    return result


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python examples/demo_v02.py NEW_OUTPUT_DIRECTORY")
    output = Path(sys.argv[1])
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        entry = {"startedDateTime": "2026-01-01T00:00:00Z", "time": 200,
                 "request": {"method": "GET", "url": "https://synthetic.example/api?token=DEMO_ONLY",
                             "headers": [{"name": "Authorization", "value": "DEMO_ONLY"}]},
                 "response": {"status": 200, "bodySize": 400,
                              "content": {"size": 400, "mimeType": "application/json", "text": "DEMO_ONLY"}}}
        before = {"log": {"entries": [copy.deepcopy(entry) for _ in range(2)]}}
        after = copy.deepcopy(before)
        after["log"]["entries"].append(copy.deepcopy(entry))
        for item in after["log"]["entries"]:
            item["time"] = 100
        after["log"]["entries"][-1]["response"]["status"] = 503
        for name, document in (("before.har", before), ("after.har", after)):
            (root / name).write_text(json.dumps(document), encoding="utf-8")
        (root / "invalid.har").write_text("deliberately invalid", encoding="utf-8")
        run("batch", root / "before.har", root / "after.har", root / "invalid.har",
            "-o", output / "batch", expected=1)
        first, second = output / "batch/capture-0001.har", output / "batch/capture-0002.har"
        run("verify", first)
        run("verify", second)
        run("review", first, "-o", output / "privacy-review.json")
        run("compare", first, second, "-o", output / "comparison.json")
    print("Created batch manifest, guided review, and aggregate comparison using synthetic data only.")


if __name__ == "__main__":
    main()
