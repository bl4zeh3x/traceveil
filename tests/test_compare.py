import copy
import json
import random
import unittest

from traceveil.compare import compare_captures
from traceveil.core import sanitize
import test_traceveil as baseline
from test_traceveil import CANARY, example


class CompareTests(unittest.TestCase):
    def test_known_changes_and_no_mutation(self):
        left = sanitize(example())
        raw = example()
        raw['log']['entries'][0]['time'] = 247
        raw['log']['entries'][0]['response']['status'] = 503
        raw['log']['entries'][0]['response']['bodySize'] = 84
        right = sanitize(raw)
        originals = copy.deepcopy((left, right))
        result = compare_captures(left, right)
        self.assertEqual(result['changes']['total_request_ms'], {'delta': 123.5, 'percent': 100})
        self.assertEqual(result['changes']['known_response_bytes']['delta'], 42)
        self.assertEqual(result['changes']['error_responses']['delta'], 1)
        self.assertEqual((left, right), originals)
        for value in ('host-1', 'route-1', 'private.example', CANARY, '2000-01-01'):
            self.assertNotIn(value, json.dumps(result))

    def test_rejects_raw_and_tampered_captures_on_both_sides(self):
        safe = sanitize(example())
        tampered = copy.deepcopy(safe)
        tampered['log']['entries'][0]['_private'] = CANARY
        for unsafe in (example(), tampered):
            for left, right in ((safe, unsafe), (unsafe, safe)):
                with self.assertRaises(ValueError) as ctx:
                    compare_captures(left, right)
                self.assertNotIn(CANARY, str(ctx.exception))

    def test_empty_and_zero_baselines_are_finite(self):
        empty = sanitize({'log': {'entries': []}})
        result = compare_captures(empty, sanitize(example()))
        self.assertEqual(result['before']['requests'], 0)
        self.assertIsNone(result['changes']['requests']['percent'])
        json.dumps(result, allow_nan=False)
        self.assertEqual(compare_captures(empty, empty)['after']['p95_request_ms'], 0)

    def test_missing_body_size_is_counted_as_unknown(self):
        raw = example()
        del raw['log']['entries'][0]['response']['bodySize']
        result = compare_captures(sanitize(raw), sanitize(raw))
        self.assertEqual(result['before']['unknown_response_sizes'], 1)
        self.assertEqual(result['before']['known_response_bytes'], 0)

    def test_unrelated_endpoints_never_get_aligned(self):
        other = example()
        other['log']['entries'][0]['request']['url'] = 'https://unrelated.example/different'
        self.assertEqual(compare_captures(sanitize(example()), sanitize(other))['changes']['requests']['delta'], 0)

    def test_percentiles_and_status_classes(self):
        raw = example()
        template = raw['log']['entries'][0]
        raw['log']['entries'] = [copy.deepcopy(template) for _ in range(20)]
        for i, entry in enumerate(raw['log']['entries'], 1):
            entry['time'] = i
            entry['response']['status'] = 0 if i == 20 else 200
        result = compare_captures(sanitize(raw), sanitize(raw))['before']
        self.assertEqual((result['median_request_ms'], result['p95_request_ms']), (10.5, 19))
        self.assertEqual(result['status_classes'], {'2xx': 19, 'unknown': 1})

    def test_randomized_aggregate_arithmetic(self):
        rng = random.Random(310026)
        for _ in range(200):
            raw = example()
            raw['log']['entries'] = [copy.deepcopy(raw['log']['entries'][0])
                                     for _ in range(rng.randrange(0, 40))]
            for entry in raw['log']['entries']:
                entry['time'] = rng.randrange(1000)
            result = compare_captures(sanitize(raw), sanitize(raw))
            self.assertEqual(result['before']['requests'], len(raw['log']['entries']))
            self.assertEqual(result['changes']['total_request_ms']['delta'], 0)
            self.assertEqual(result['before']['total_request_ms'], sum(e['time'] for e in raw['log']['entries']))


class CompareCliTests(unittest.TestCase):
    setUp = baseline.CliTests.setUp
    run_cli = baseline.CliTests.run_cli

    def test_cli_counts_refuses_raw_and_no_overwrite(self):
        clean = self.root / 'clean.har'
        clean.write_text(json.dumps(sanitize(example())))
        for args in [('compare', clean), ('compare', clean, clean, clean),
                     ('compare', self.source, clean)]:
            code, out, err = self.run_cli(*args)
            self.assertEqual(code, 2)
            self.assertNotIn(CANARY, out + err)
        code, out, err = self.run_cli('compare', clean, clean)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['changes']['requests']['delta'], 0)
        target = self.root / 'comparison.json'
        self.assertEqual(self.run_cli('compare', clean, clean, '-o', target)[0], 0)
        original = target.read_bytes()
        self.assertEqual(self.run_cli('compare', clean, clean, '-o', target)[0], 2)
        self.assertEqual(target.read_bytes(), original)
