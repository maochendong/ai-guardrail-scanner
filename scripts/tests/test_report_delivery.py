import ast
import copy
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from report_schema import (CONTENT_TRUST, INLINE_REPORT_BYTES, OMITTED_REASON,
                           REPORT_FILES, verified_report_content)


class ReportDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name).resolve()
        self.scan_id = '12345678-1234-4234-8234-123456789abc'
        self.directory = self.output / self.scan_id
        self.directory.mkdir()
        self.state = {'scanId': self.scan_id, 'state': 'COMPLETED', 'unknowns': 1}
        self.artifacts = {fmt: str(self.directory / name) for fmt, name in REPORT_FILES.items()}
        for path in self.artifacts.values():
            Path(path).write_bytes('{"message":"安全"}\r\n'.encode('utf-8'))

    def result(self, fmt='json'):
        data = Path(self.artifacts[fmt]).read_bytes()
        omitted = len(data) > INLINE_REPORT_BYTES
        result = {'scanId': self.scan_id, 'status': copy.deepcopy(self.state),
                  'format': fmt, 'contentTrust': CONTENT_TRUST,
                  'artifacts': dict(self.artifacts), 'contentOmitted': omitted}
        result.update({'reason': OMITTED_REASON} if omitted else {'content': data.decode('utf-8')})
        return result

    def verify(self, result, fmt='json'):
        return verified_report_content(result, fmt, self.state, self.output, 'fixture')

    def test_inline_all_formats_match_utf8_and_preserve_line_endings(self):
        for fmt in REPORT_FILES:
            with self.subTest(format=fmt):
                self.assertEqual('{"message":"安全"}\r\n', self.verify(self.result(fmt), fmt))

    def test_exact_byte_limit_stays_inline(self):
        Path(self.artifacts['json']).write_bytes(b'x' * INLINE_REPORT_BYTES)
        result = self.result()
        self.assertFalse(result['contentOmitted'])
        self.assertEqual(INLINE_REPORT_BYTES, len(self.verify(result)))

    def test_omitted_all_formats_use_complete_file_and_utf8_byte_limit(self):
        content = '界' * (INLINE_REPORT_BYTES // 3 + 1)
        self.assertLess(len(content), INLINE_REPORT_BYTES)
        for fmt in REPORT_FILES:
            with self.subTest(format=fmt):
                Path(self.artifacts[fmt]).write_bytes(content.encode('utf-8'))
                result = self.result(fmt)
                self.assertTrue(result['contentOmitted'])
                self.assertNotIn('content', result)
                self.assertEqual(content, self.verify(result, fmt))

    def test_metadata_mismatches_are_rejected(self):
        changes = [('scanId', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
                   ('format', 'sarif'), ('contentTrust', 'trusted'),
                   ('status', dict(self.state, state='RUNNING')),
                   ('contentOmitted', 0), ('extra', 'unexpected')]
        for key, value in changes:
            with self.subTest(field=key):
                result = self.result()
                result[key] = value
                with self.assertRaises(AssertionError):
                    self.verify(result)

    def test_inline_text_mismatch_or_missing_content_is_rejected(self):
        for value in ['different', None]:
            with self.subTest(content=value):
                result = self.result()
                if value is None:
                    del result['content']
                else:
                    result['content'] = value
                with self.assertRaises(AssertionError):
                    self.verify(result)

    def test_small_omitted_or_large_inline_is_rejected(self):
        result = self.result()
        del result['content']
        result.update(contentOmitted=True, reason=OMITTED_REASON)
        with self.assertRaises(AssertionError):
            self.verify(result)
        content = 'x' * (INLINE_REPORT_BYTES + 1)
        Path(self.artifacts['json']).write_bytes(content.encode())
        result = self.result()
        del result['reason']
        result.update(contentOmitted=False, content=content)
        with self.assertRaises(AssertionError):
            self.verify(result)

    def test_omitted_reason_missing_invalid_or_content_present_is_rejected(self):
        Path(self.artifacts['json']).write_bytes(b'x' * (INLINE_REPORT_BYTES + 1))
        for change in ['missing', 'invalid', 'content']:
            with self.subTest(change=change):
                result = self.result()
                if change == 'missing':
                    del result['reason']
                elif change == 'invalid':
                    result['reason'] = 'other'
                else:
                    result['content'] = ''
                with self.assertRaises(AssertionError):
                    self.verify(result)

    def test_foreign_or_missing_artifact_metadata_is_rejected(self):
        for change in ['foreign', 'missing', 'relative', 'extra']:
            with self.subTest(change=change):
                result = self.result()
                if change == 'foreign':
                    result['artifacts']['json'] = str(self.output / 'report.json')
                elif change == 'relative':
                    result['artifacts']['json'] = 'report.json'
                elif change == 'missing':
                    del result['artifacts']['sarif']
                else:
                    result['artifacts']['raw'] = str(self.output / 'raw')
                with self.assertRaises(AssertionError):
                    self.verify(result)

    def test_missing_file_is_rejected_even_when_content_is_inline(self):
        result = self.result()
        Path(self.artifacts['json']).unlink()
        with self.assertRaises(AssertionError):
            self.verify(result)

    def test_linked_file_or_scan_directory_is_rejected(self):
        result = self.result()
        path = Path(self.artifacts['json'])
        target = self.output / 'elsewhere.json'
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(AssertionError):
            self.verify(result)
        path.unlink()
        target.rename(path)
        relocated = self.output / 'relocated'
        self.directory.rename(relocated)
        self.directory.symlink_to(relocated, target_is_directory=True)
        with self.assertRaises(AssertionError):
            self.verify(result)

    def test_omitted_file_must_still_be_valid_utf8(self):
        Path(self.artifacts['json']).write_bytes(b'\xff' * (INLINE_REPORT_BYTES + 1))
        result = self.result()
        with self.assertRaises(UnicodeDecodeError):
            self.verify(result)

    def test_noncanonical_id_or_nonterminal_state_is_rejected(self):
        for field, value in [('scanId', '../outside'), ('state', 'RUNNING')]:
            with self.subTest(field=field):
                original = dict(self.state)
                self.state[field] = value
                result = self.result()
                with self.assertRaises(AssertionError):
                    self.verify(result)
                self.state = original

    def test_both_scripts_invoke_shared_delivery_validation(self):
        for name in ['verify-runtime-matrix.py', 'verify-codex-integration.py']:
            tree = ast.parse((SCRIPTS / name).read_text())
            imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
                       and node.module == 'report_schema']
            self.assertEqual(1, len(imports), name)
            self.assertIn('verified_report_content', [alias.name for alias in imports[0].names])
            self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                                and node.func.id == 'verified_report_content' for node in ast.walk(tree)), name)


if __name__ == '__main__':
    unittest.main()
