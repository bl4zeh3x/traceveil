"""Offline command line entry point. No network dependencies or telemetry."""

import argparse
import json
from pathlib import Path
import sys
from .core import inspect_har, is_sanitized, sanitize
from .report import render_report

from .storage import MAX_BYTES, load, write_new


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline HAR privacy review and conservative export")
    parser.add_argument("command", choices=["inspect", "sanitize", "report", "verify", "batch"])
    parser.add_argument("input", type=Path)
    parser.add_argument("additional_inputs", nargs="*", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "batch":
            from .batch import sanitize_batch
            if args.output is None:
                raise ValueError("batch requires a new output directory")
            result = sanitize_batch([args.input, *args.additional_inputs], args.output)
            print(json.dumps(result, indent=2, allow_nan=False))
            return 0 if result["failed"] == 0 else 1
        if args.additional_inputs:
            raise ValueError("This command accepts one input")
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
