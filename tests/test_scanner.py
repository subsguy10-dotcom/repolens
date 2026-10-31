import tempfile
import unittest
from pathlib import Path
from repolens.scanner import analyze

class ScannerTests(unittest.TestCase):
    def test_missing_essentials(self):
        with tempfile.TemporaryDirectory() as folder:
            result = analyze(folder)
            self.assertLess(result['score'], 100)
            self.assertIn('Missing README', [f['title'] for f in result['findings']])

    def test_detects_secret_pattern_without_echoing_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'app.py').write_text('api_key = ' + chr(34) + 'synthetic' + '123456789' + chr(34))
            result = analyze(folder)
            self.assertIn('Potential hardcoded credential', [f['title'] for f in result['findings']])
            self.assertNotIn('synthetic' + '123456789', str(result))

    def test_skips_vendor_directories(self):
        with tempfile.TemporaryDirectory() as folder:
            vendor = Path(folder) / 'node_modules'
            vendor.mkdir()
            (vendor / 'bad.js').write_text('password = ' + chr(34) + 'synthetic' + '123456789' + chr(34))
            self.assertEqual(analyze(folder)['files'], 0)

    def test_safe_file_count(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'README.md').write_text('# Hello')
            (Path(folder) / 'hello.py').write_text('print("hello")\n')
            report = analyze(folder)
            self.assertEqual(report['files'], 2)
            self.assertEqual(report['lines_of_code'], 1)

if __name__ == '__main__':
    unittest.main()
