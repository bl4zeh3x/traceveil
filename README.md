# Traceveil

Share useful network evidence without copying the original browser payloads.

Traceveil is an offline Python tool for reviewing and sanitizing HAR files from browser developer tools. A small allowlist reconstructs the archive instead of trying to recognize every possible secret. It keeps request order, relationships, timing, response status and size, while removing original hostnames, routes, headers, cookies, queries, bodies, timestamps, page titles and custom metadata.

## Core workflows

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

## v0.2 release candidate: three new workflows

The v0.1.0 release remains available. This branch prepares v0.2; it is not a claim of program submission or reward approval.

| Problem in v0.1 | New workflow | Observable benefit |
|---|---|---|
| Each capture needed a separate export and filename decision | Batch sanitization | Process up to 1,000 captures into one new directory, isolate failures, and get an integrity manifest |
| Inspection counted removable fields but did not guide the sharing decision | Guided privacy review | See a removal summary, a next step, and a checklist for timing, size and activity-pattern disclosures |
| Comparing captures required manually reading separate reports | Aggregate comparison | Compare request counts, response sizes, duration distributions and errors without aligning endpoint identities |

```sh
traceveil batch before.har after.har -o exports
traceveil review exports/capture-0001.har -o privacy-review.json
traceveil compare exports/capture-0001.har exports/capture-0002.har -o comparison.json
```

Batch requires a **new directory**, even if an existing one is empty. Outputs use neutral numbered names; manifest input IDs follow command-line argument order. Original filenames and exception payloads are never copied. A failed file does not prevent later files from being processed. Exit codes: `0` all succeeded, `1` some or all files failed (inspect the manifest), `2` invalid invocation or destination setup/manifest failure. An interrupted run may contain incomplete outputs without a completed manifest; retain originals and retry in a new directory. On POSIX the directory is created with mode 0700 and files with mode 0600; Windows permissions depend on the parent ACL.

`review` returns `1` when the input needs sanitization and `0` when it is canonical. **Neither result approves sharing.** The residual-risk checklist still requires judgment about the intended recipient. The report prints JSON unless `-o` names a new file.

`compare` requires **two canonical sanitized captures**; raw or modified captures are rejected with exit code `2`. It returns aggregate changes only, with no endpoint labels or identity inference. A percentage change from zero is `null`. Response-byte totals exclude unknown sizes, whose count is reported separately. Summed request durations are not wall-clock duration because requests can overlap. Aggregates may still fingerprint activity. Existing outputs are never overwritten.

The canonical HAR creator version remains `0.1.0` intentionally: v0.2 adds workflows without changing the conservative format or invalidating existing exports.

### Try the three workflows with synthetic data

Install the package from this branch, then run:

```sh
python examples/demo_v02.py demo-output
```

The script runs the real CLI to produce a batch with one deliberately invalid input, a guided review, and an aggregate comparison. It uses only synthetic data, requires a new output directory and performs no network requests. See [the walkthrough](docs/v0.2.md) for expected results and acceptance criteria.

Development disclosure: the v0.2 changes were developed with AI assistance. Traceveil has no runtime AI service or external data transmission.

## Development

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m traceveil inspect examples/demo.har
PYTHONPATH=src python -m traceveil sanitize examples/demo.har -o /tmp/traceveil-share.har
PYTHONPATH=src python -m traceveil report examples/demo.har -o /tmp/traceveil-review.html
```

The demo contains synthetic data only. Tests cover payload removal, idempotence, malformed inputs, report injection, CLI exit codes and refusal to overwrite files.

Built for [Hack Club Stardance](https://stardance.hackclub.com/), under the Frictionless mission. MIT licensed.
