import contextlib
import copy
import io
import json
import os
from pathlib import Path
import random
import tempfile
import unittest

from traceveil import inspect_har, is_sanitized, sanitize
from traceveil.cli import load, main
from traceveil.report import render_report

CANARY = "SYNTHETIC_PRIVATE_VALUE_7429"


def example():
    return {"log": {"version": "1.2", "creator": {"name": CANARY},
        "pages": [{"title": CANARY}], "_vendor": CANARY,
        "entries": [{"startedDateTime": "2026-10-26T10:00:00Z", "time": 123.5,
          "request": {"method": "GET", "url": f"https://user:{CANARY}@private.example/{CANARY}?key={CANARY}#{CANARY}",
                      "headers": [{"name": "Authorization", "value": CANARY}],
                      "cookies": [{"name": "session", "value": CANARY}],
                      "queryString": [{"name": "key", "value": CANARY}],
                      "postData": {"text": CANARY}, "_extension": CANARY},
          "response": {"status": 200, "statusText": CANARY,
                       "headers": [{"name": "Set-Cookie", "value": CANARY}],
                       "cookies": [{"name": "secret", "value": CANARY}],
                       "content": {"size": 42, "mimeType": "application/json", "text": CANARY},
                       "redirectURL": CANARY, "bodySize": 42},
          "timings": {"wait": 100, "receive": 23.5, "_private": CANARY},
          "serverIPAddress": CANARY, "connection": CANARY, "_initiator": {"stack": CANARY}}]}}


class SanitizerTests(unittest.TestCase):
    def test_removes_canary_everywhere(self):
        output = json.dumps(sanitize(example()))
        self.assertNotIn(CANARY, output)
        self.assertNotIn("private.example", output)
        self.assertNotIn("2026-10-26", output)

    def test_does_not_mutate_input(self):
        source = example()
        original = copy.deepcopy(source)
        sanitize(source)
        self.assertEqual(source, original)

    def test_retains_debug_metrics(self):
        entry = sanitize(example())["log"]["entries"][0]
        self.assertEqual((entry["time"], entry["response"]["status"], entry["response"]["bodySize"]), (123.5, 200, 42))

    def test_endpoint_relationships(self):
        source = example()
        second = copy.deepcopy(source["log"]["entries"][0])
        source["log"]["entries"].append(second)
        third = copy.deepcopy(second)
        third["request"]["url"] = "https://other.example/new?token=private"
        source["log"]["entries"].append(third)
        urls = [e["request"]["url"] for e in sanitize(source)["log"]["entries"]]
        self.assertEqual(urls[0], urls[1])
        self.assertNotEqual(urls[0], urls[2])

    def test_relative_times(self):
        source = example()
        second = copy.deepcopy(source["log"]["entries"][0])
        second["startedDateTime"] = "2026-10-26T10:00:02.500Z"
        source["log"]["entries"].append(second)
        entries = sanitize(source)["log"]["entries"]
        self.assertEqual(entries[1]["startedDateTime"], "2000-01-01T00:00:02.500000Z")

    def test_idempotent(self):
        clean = sanitize(example())
        self.assertEqual(clean, sanitize(clean))
        self.assertTrue(is_sanitized(clean))
        self.assertFalse(is_sanitized(example()))

    def test_empty_archive(self):
        self.assertTrue(is_sanitized(sanitize({"log": {"entries": []}})))

    def test_malformed_structure(self):
        for document in [None, [], {}, {"log": {}}, {"log": {"entries": [None]}},
                         {"log": {"entries": [{"request": {}}]}}]:
            with self.subTest(document=document), self.assertRaises(ValueError):
                sanitize(document)

    def test_invalid_urls_do_not_echo_values(self):
        for url in [None, 42, "file:///private", "javascript:alert(1)", "https://[bad", "https://host:bad/", CANARY]:
            source = example()
            source["log"]["entries"][0]["request"]["url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError) as ctx:
                sanitize(source)
            self.assertNotIn(CANARY, str(ctx.exception))

    def test_unknown_methods_and_mime(self):
        for method in [None, {}, [], CANARY]:
            source = example()
            source["log"]["entries"][0]["request"]["method"] = method
            source["log"]["entries"][0]["response"]["content"]["mimeType"] = CANARY
            entry = sanitize(source)["log"]["entries"][0]
            self.assertEqual(entry["request"]["method"], "OTHER")
            self.assertEqual(entry["response"]["content"]["mimeType"], "application/octet-stream")

    def test_extreme_and_nonfinite_metrics(self):
        for value in [float("nan"), float("inf"), -3, True, "private", 10**1000]:
            source = example()
            source["log"]["entries"][0]["time"] = value
            clean = sanitize(source)
            json.dumps(clean, allow_nan=False)
            self.assertEqual(clean["log"]["entries"][0]["time"], 0)

    def test_inspector_does_not_copy_secrets(self):
        report = inspect_har(example())
        self.assertEqual(len(report["findings"]), 7)
        self.assertNotIn(CANARY, json.dumps(report))

    def test_report_cannot_inject_source_html(self):
        source = example()
        source["log"]["entries"][0]["request"]["method"] = '<script>alert("x")</script>'
        output = render_report(source)
        self.assertNotIn("<script", output)
        self.assertNotIn(CANARY, output)
        self.assertIn("default-src 'none'", output)

    def test_randomized_metadata_is_discarded(self):
        rng = random.Random(261026)
        for _ in range(250):
            source = example()
            marker = f"PRIVATE_{rng.getrandbits(64)}"
            source["log"][marker] = {"secret": marker}
            source["log"]["entries"][0][marker] = marker
            clean = sanitize(source)
            self.assertNotIn(marker, json.dumps(clean))
            self.assertEqual(clean, sanitize(clean))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.har"
        self.source.write_text(json.dumps(example()))

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(map(str, args)))
        return code, out.getvalue(), err.getvalue()

    def test_full_round_trip(self):
        clean = self.root / "clean.har"
        report = self.root / "review.html"
        self.assertEqual(self.run_cli("sanitize", self.source, "-o", clean)[0], 0)
        self.assertEqual(self.run_cli("verify", clean)[0], 0)
        self.assertEqual(self.run_cli("verify", self.source)[0], 1)
        self.assertEqual(self.run_cli("report", clean, "-o", report)[0], 0)
        self.assertNotIn(CANARY, report.read_text())

    def test_refuses_source_overwrite(self):
        before = self.source.read_bytes()
        self.assertEqual(self.run_cli("sanitize", self.source, "-o", self.source)[0], 2)
        self.assertEqual(self.source.read_bytes(), before)

    def test_refuses_existing_output(self):
        target = self.root / "existing.har"
        target.write_text("preserve me")
        self.assertEqual(self.run_cli("sanitize", self.source, "-o", target)[0], 2)
        self.assertEqual(target.read_text(), "preserve me")

    @unittest.skipIf(os.name == "nt", "POSIX symlink permissions")
    def test_refuses_output_symlink(self):
        target = self.root / "alias.har"
        target.symlink_to(self.source)
        before = self.source.read_bytes()
        self.assertEqual(self.run_cli("sanitize", self.source, "-o", target)[0], 2)
        self.assertEqual(self.source.read_bytes(), before)

    def test_errors_do_not_echo_filename_or_secrets(self):
        source = self.root / CANARY
        source.write_text('{"secret": "' + CANARY)
        code, out, err = self.run_cli("inspect", source)
        self.assertEqual(code, 2)
        self.assertNotIn(CANARY, out + err)

    def test_nonfinite_json_rejected(self):
        self.source.write_text('{"log":{"entries":[]},"bad":NaN}')
        with self.assertRaises(ValueError):
            load(self.source)

    def test_output_required(self):
        self.assertEqual(self.run_cli("sanitize", self.source)[0], 2)

    def test_inspect_has_no_output_side_effect(self):
        target = self.root / "no-file"
        self.assertEqual(self.run_cli("inspect", self.source, "-o", target)[0], 2)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
