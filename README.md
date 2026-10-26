# Traceveil

Share useful network evidence without copying the original browser payloads.

Traceveil is an offline Python tool for reviewing and sanitizing HAR files from browser developer tools. A small allowlist reconstructs the archive instead of trying to recognize every possible secret. It keeps request order, relationships, timing, response status and size, while removing original hostnames, routes, headers, cookies, queries, bodies, timestamps, page titles and custom metadata.

## Three workflows

1. **Inspect:** count common exposure surfaces without printing their values.
2. **Sanitize and review:** produce a conservative HAR and a standalone HTML network report.
3. **Verify:** use an exit code to reject files that differ from the canonical conservative format.

```sh
python -m pip install .
traceveil inspect capture.har
traceveil sanitize capture.har -o share.har
traceveil report share.har -o review.html
traceveil verify share.har
```

Python 3.10 or later is required. Runtime dependencies: none. No uploads, telemetry or network access. Outputs must be new files; existing files and symlinks are refused. Inputs larger than 50 MiB are rejected. Original archives remain on your computer.

## What survives

Repeated endpoints receive consistent labels within one archive, such as `https://host-1.invalid/route-1`. The labels are not stable across different files. Exact dates become relative offsets from a fixed date. Known MIME types are retained; other types become `application/octet-stream`.

This conservative export intentionally loses details needed for full request replay. Timing, response sizes and request relationships can still identify an activity. **Review before sharing. This is not a guarantee of anonymity or compliance.** The inspector is a review aid, not a comprehensive secret detector.

## Development

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m traceveil inspect examples/demo.har
PYTHONPATH=src python -m traceveil sanitize examples/demo.har -o /tmp/traceveil-share.har
PYTHONPATH=src python -m traceveil report examples/demo.har -o /tmp/traceveil-review.html
```

The demo contains synthetic data only. Tests cover payload removal, idempotence, malformed inputs, report injection, CLI exit codes and refusal to overwrite files.

Built for [Hack Club Stardance](https://stardance.hackclub.com/), under the Frictionless mission. MIT licensed.
