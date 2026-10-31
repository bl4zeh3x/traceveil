import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from traceveil.batch import sanitize_batch
from traceveil.cli import main
from traceveil.core import is_sanitized
from test_traceveil import CANARY, example


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / (CANARY + '.har')
        self.source.write_text(json.dumps(example()))
        self.output = self.root / 'batch'

    def test_multiple_inputs_and_manifest_are_private(self):
        before = self.source.read_bytes()
        result = sanitize_batch([self.source, self.source], self.output)
        self.assertEqual((result['succeeded'], result['failed']), (2, 0))
        self.assertEqual(result, json.loads((self.output / 'manifest.json').read_text()))
        for item in result['files']:
            target = self.output / item['output']
            self.assertTrue(is_sanitized(json.loads(target.read_text())))
            self.assertEqual(item['sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertNotIn(CANARY, ''.join(p.read_text() for p in self.output.iterdir()))
        self.assertEqual(self.source.read_bytes(), before)

    def test_same_basename_cannot_collide(self):
        other = self.root / 'other'
        other.mkdir()
        second = other / self.source.name
        second.write_bytes(self.source.read_bytes())
        result = sanitize_batch([self.source, second], self.output)
        self.assertEqual(len({x['output'] for x in result['files']}), 2)

    def test_invalid_input_is_isolated(self):
        bad = self.root / 'bad.har'
        bad.write_text('{"secret":"' + CANARY)
        result = sanitize_batch([bad, self.source, self.root / 'missing'], self.output)
        self.assertEqual((result['succeeded'], result['failed']), (1, 2))
        self.assertEqual(result['files'][1]['input_id'], 2)
        self.assertNotIn(CANARY, json.dumps(result))

    def test_existing_directory_is_untouched(self):
        self.output.mkdir()
        sentinel = self.output / 'capture-0001.har'
        sentinel.write_text('keep')
        with self.assertRaises(FileExistsError):
            sanitize_batch([self.source], self.output)
        self.assertEqual(sentinel.read_text(), 'keep')
        self.assertEqual(list(self.output.iterdir()), [sentinel])

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink permissions')
    def test_existing_directory_symlink_is_refused(self):
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            sanitize_batch([self.source], self.output)
        self.assertFalse((self.root / 'manifest.json').exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX mode bits')
    def test_private_permissions(self):
        sanitize_batch([self.source], self.output)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        for target in self.output.iterdir():
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_output_bytes_are_utf8_with_lf_on_every_platform(self):
        from traceveil.storage import write_new
        text = 'first line\nUnicode: café\n'
        target = self.root / 'text.json'
        write_new(target, text)
        self.assertEqual(target.read_bytes(), text.encode('utf-8'))

    def test_batch_size_bounds_before_side_effects(self):
        for inputs in ([], [self.source] * 1001):
            with self.assertRaises(ValueError):
                sanitize_batch(inputs, self.output)
        self.assertFalse(self.output.exists())

    def test_output_failure_does_not_stop_other_files(self):
        from traceveil.storage import write_new
        def fail_one(path, text):
            if path.name == 'capture-0001.har':
                raise OSError(CANARY)
            return write_new(path, text)
        with patch('traceveil.batch.write_new', side_effect=fail_one):
            result = sanitize_batch([self.source, self.source], self.output)
        self.assertEqual((result['succeeded'], result['failed']), (1, 1))
        self.assertNotIn(CANARY, json.dumps(result))

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(map(str, args)))
        return code, out.getvalue(), err.getvalue()

    def test_cli_success_and_partial_failure(self):
        self.assertEqual(self.run_cli('batch', self.source, '-o', self.output)[0], 0)
        code, out, err = self.run_cli('batch', self.source, self.root / CANARY,
                                     '-o', self.root / 'partial')
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)['failed'], 1)
        self.assertNotIn(CANARY, out + err)

    def test_cli_requires_output(self):
        self.assertEqual(self.run_cli('batch', self.source)[0], 2)

    def test_old_commands_refuse_extra_inputs(self):
        self.assertEqual(self.run_cli('inspect', self.source, self.source)[0], 2)
