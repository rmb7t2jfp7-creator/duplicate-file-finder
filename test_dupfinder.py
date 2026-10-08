import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import dupfinder as d


class FinderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def invoke(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return d.main(args)

    def test_three_copies_count_n_minus_one(self):
        for name in ['a', 'b', 'folder/c']:
            self.put(name, b'abcdef')
        self.put('different-same-size', b'ghijkl')
        result = d.scan(self.root)
        self.assertEqual(result['duplicate_groups'], 1)
        self.assertEqual(result['redundant_bytes'], 12)
        self.assertEqual(result['groups'][0]['distinct_files'], 3)

    def test_empty_duplicates_have_zero_redundant_bytes(self):
        self.put('a', b''); self.put('b', b'')
        result = d.scan(self.root)
        self.assertEqual(result['duplicate_groups'], 1)
        self.assertEqual(result['redundant_bytes'], 0)

    def test_unique_sizes_do_not_get_hashed(self):
        self.put('a', b'a'); self.put('b', b'ab')
        with patch.object(d, '_hash_file', side_effect=AssertionError('should not hash')):
            self.assertEqual(d.scan(self.root)['files_hashed'], 0)

    def test_hardlinks_not_counted_as_another_copy(self):
        first = self.put('a', b'abc'); self.put('b', b'abc')
        try: os.link(first, self.root / 'alias')
        except OSError: self.skipTest('hardlinks unavailable')
        result = d.scan(self.root)
        self.assertEqual(result['hardlink_alias_count'], 1)
        self.assertEqual(result['redundant_bytes'], 3)
        self.assertEqual(result['groups'][0]['distinct_files'], 2)

    def test_symlinks_and_directory_loop_not_followed(self):
        a = self.put('a', b'abc')
        try:
            (self.root / 'alias').symlink_to(a)
            (self.root / 'loop').symlink_to(self.root, target_is_directory=True)
        except OSError: self.skipTest('symlinks unavailable')
        result = d.scan(self.root)
        self.assertEqual(result['files_seen'], 1)
        self.assertEqual(len(result['skipped']), 2)
        self.assertEqual(result['duplicate_groups'], 0)
        with self.assertRaises(ValueError): d.scan(self.root / 'loop')

    def test_changed_before_hash_skipped(self):
        self.put('a', b'abc'); self.put('b', b'abc')
        original = d._hash_file
        def change(candidate):
            if candidate.path.name == 'a': candidate.path.write_bytes(b'changed')
            return original(candidate)
        with patch.object(d, '_hash_file', side_effect=change): result = d.scan(self.root)
        self.assertEqual(result['duplicate_groups'], 0)
        self.assertIn('changed before', result['skipped'][0]['reason'])

    def test_changed_during_hash_detected(self):
        path = self.put('a', b'abcdef')
        candidate = d.Candidate(path, path.stat(), [])
        original = d.hashlib.sha256
        class MutatingDigest:
            def __init__(self): self.digest = original()
            def update(self, chunk):
                self.digest.update(chunk)
                path.write_bytes(b'changed-content')
            def hexdigest(self): return self.digest.hexdigest()
        with patch.object(d.hashlib, 'sha256', MutatingDigest):
            with self.assertRaises(d.ChangedFileError): d._hash_file(candidate)

    def test_read_error_reported_without_false_group(self):
        self.put('a', b'abc'); self.put('b', b'abc')
        with patch.object(d, '_hash_file', side_effect=PermissionError('read denied')): result = d.scan(self.root)
        self.assertEqual(result['duplicate_groups'], 0)
        self.assertEqual(len(result['skipped']), 2)

    def test_html_and_terminal_escape_filenames(self):
        self.put('<img onerror=x>', b'x'); self.put('copy\x1b[31m', b'x')
        result = d.scan(self.root)
        self.assertNotIn('<img onerror=', d.html_report(result))
        self.assertIn('&lt;img', d.html_report(result))
        self.assertNotIn('\x1b', d.text_report(result))

    def test_existing_output_and_aliases_are_preserved(self):
        source = self.put('a', b'precious')
        self.assertEqual(self.invoke([str(self.root), '--json', str(source)]), 2)
        self.assertEqual(source.read_bytes(), b'precious')
        try: os.link(source, self.root / 'alias.json')
        except OSError: return
        self.assertEqual(self.invoke([str(self.root), '--json', str(self.root / 'alias.json')]), 2)
        self.assertEqual(source.read_bytes(), b'precious')

    def test_new_outputs_inside_scan_tree_and_same_path_rejected(self):
        self.put('a', b'ab'); self.put('b', b'ab')
        output = self.root / 'report.json'
        self.assertEqual(self.invoke([str(self.root), '--json', str(output), '--html', str(output)]), 2)
        self.assertFalse(output.exists())
        self.assertEqual(self.invoke([str(self.root), '--json', str(output)]), 0)
        result = json.loads(output.read_text())
        self.assertEqual(result['files_seen'], 2)
        self.assertEqual(result['redundant_bytes'], 2)

    def test_invalid_directory(self):
        self.assertEqual(self.invoke([str(self.root / 'missing')]), 2)


if __name__ == '__main__':
    unittest.main()
