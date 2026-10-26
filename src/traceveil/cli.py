"""Offline command line entry point. No network dependencies or telemetry."""

import argparse
import json
import os
from pathlib import Path
import sys
from .core import inspect_har, is_sanitized, sanitize
from .report import render_report

MAX_BYTES = 50 * 1024 * 1024


def load(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Input exceeds the 50 MiB limit")
    try:
        return json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError):
        raise ValueError("Input is not valid finite JSON") from None


def write_new(path, text):
    # O_EXCL refuses existing files and symlinks; never overwrite the source.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline HAR privacy review and conservative export")
    parser.add_argument("command", choices=["inspect", "sanitize", "report", "verify"])
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command in {"sanitize", "report"} and args.output is None:
            raise ValueError("sanitize and report require --output")
        if args.command in {"inspect", "verify"} and args.output is not None:
            raise ValueError("inspect and verify do not write files")
        document = load(args.input)
        if args.command == "verify":
            valid = is_sanitized(document)
            print("Canonical conservative HAR" if valid else "Not a canonical conservative HAR")
            return 0 if valid else 1
        if args.command == "inspect":
            print(json.dumps(inspect_har(document), indent=2, allow_nan=False))
            return 0
        result = render_report(document) if args.command == "report" else json.dumps(
            sanitize(document), indent=2, allow_nan=False) + "\n"
        write_new(args.output, result)
        print("Wrote new local output. Review before sharing.")
        return 0
    except (OSError, ValueError, TypeError, RecursionError):
        # Never echo raw URLs, filenames, archive values or exception payloads.
        print("Traceveil could not process this input or create a new output. Check format, size, and output availability.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
