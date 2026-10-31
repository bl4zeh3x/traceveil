import copy
import json
import unittest

from traceveil.core import sanitize
from traceveil.privacy import privacy_review
import test_traceveil as baseline
from test_traceveil import CANARY, example


class PrivacyTests(unittest.TestCase):
    def test_raw_capture_gets_actionable_removal_plan(self):
        report = privacy_review(example())
        self.assertEqual(report['next_step'], 'sanitize_first')
        self.assertEqual(report['removable_surfaces']['request.headers'], 1)
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertNotIn('private.example', json.dumps(report))
        self.assertFalse(report['canonical_safe_format'])

    def test_canonical_does_not_mean_no_residual_risk(self):
        report = privacy_review(sanitize(example()))
        self.assertEqual(report['next_step'], 'manual_review')
        self.assertEqual(report['removable_surfaces'], {})
        self.assertTrue(report['canonical_safe_format'])
        self.assertEqual({r['code'] for r in report['residual_risks']},
                         {'timing_fingerprint', 'size_fingerprint', 'activity_pattern'})
        self.assertIn('cannot certify anonymity', report['notice'])

    def test_relative_timeline_and_affected_counts(self):
        document = example()
        second = copy.deepcopy(document['log']['entries'][0])
        second['startedDateTime'] = '2026-10-26T10:00:04Z'
        document['log']['entries'].append(second)
        risks = {r['code']: r['affected_entries'] for r in privacy_review(document)['residual_risks']}
        self.assertEqual(risks['relative_timeline'], 1)
        self.assertEqual(risks['size_fingerprint'], 2)

    def test_empty_capture_and_no_mutation(self):
        source = {'log': {'entries': []}}
        before = copy.deepcopy(source)
        report = privacy_review(source)
        self.assertEqual(report['entries'], 0)
        self.assertEqual(report['residual_risks'], [])
        self.assertEqual(source, before)

    def test_unknown_metadata_never_enters_review(self):
        source = sanitize(example())
        source['log']['entries'][0]['_private'] = CANARY
        report = privacy_review(source)
        self.assertEqual(report['next_step'], 'sanitize_first')
        self.assertNotIn(CANARY, json.dumps(report))

    def test_invalid_capture_rejected(self):
        with self.assertRaises(ValueError):
            privacy_review({'log': {'entries': [None]}})


class ReviewCliTests(unittest.TestCase):
    setUp = baseline.CliTests.setUp
    run_cli = baseline.CliTests.run_cli

    def test_review_exit_codes_and_output(self):
        code, out, err = self.run_cli('review', self.source)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)['next_step'], 'sanitize_first')
        self.assertNotIn(CANARY, out + err)
        clean = self.root / 'clean.har'
        clean.write_text(json.dumps(sanitize(example())))
        target = self.root / 'review.json'
        self.assertEqual(self.run_cli('review', clean, '-o', target)[0], 0)
        self.assertEqual(json.loads(target.read_text())['next_step'], 'manual_review')
        before = target.read_bytes()
        self.assertEqual(self.run_cli('review', clean, '-o', target)[0], 2)
        self.assertEqual(target.read_bytes(), before)
