"""Bounded input and exclusive, private local output shared by CLI workflows."""

import json
import os

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
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
