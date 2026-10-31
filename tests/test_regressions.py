import http.client
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from repolens.scanner import analyze
from repolens.web import make_server


class RegressionTests(unittest.TestCase):
    def test_env_secret_is_detected_and_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            secret = 'synthetic' + 'credential123456'
            Path(folder, '.env').write_text(f'password="{secret}"', encoding='utf-8')
            report = analyze(folder)
            self.assertEqual(report['scanned_text_files'], 1)
            self.assertIn('Potential hardcoded credential', [f['title'] for f in report['findings']])
            self.assertNotIn(secret, json.dumps(report))

    def test_nested_readme_does_not_replace_root_readme(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'tests').mkdir()
            Path(folder, 'tests', 'README.md').write_text('Tests', encoding='utf-8')
            titles = [f['title'] for f in analyze(folder)['findings']]
            self.assertIn('Missing README', titles)
            self.assertNotIn('No obvious tests', titles)

    def test_limit_is_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in ('a.py', 'b.py'):
                Path(folder, name).write_text('pass', encoding='utf-8')
            with patch('repolens.scanner.MAX_FILES', 1):
                report = analyze(folder)
            self.assertEqual(report['files'], 1)
            self.assertTrue(report['truncated'])
            self.assertTrue(report['warnings'])

    def test_oversized_and_binary_text_are_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'a.py').write_bytes(b'123456789')
            Path(folder, 'b.py').write_bytes(b'\xff')
            with patch('repolens.scanner.MAX_BYTES', 8):
                report = analyze(folder)
            self.assertEqual(report['skipped_text_files'], 2)

    def test_symlink_directory_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            Path(outside, 'secret.py').write_text('pass', encoding='utf-8')
            try:
                Path(folder, 'link').symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest('Symlink creation unavailable')
            self.assertEqual(analyze(folder)['files'], 0)

    def test_invalid_path(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                analyze(Path(folder, 'missing'))

    def test_cli_json_threshold_and_invalid_input(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, '-m', 'repolens.cli', folder, '--json', '--min-score', '100'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertLess(json.loads(result.stdout)['score'], 100)
            invalid = subprocess.run([sys.executable, '-m', 'repolens.cli', folder, '--min-score', '101'],
                                     capture_output=True, text=True)
            self.assertEqual(invalid.returncode, 2)

    def test_http_dashboard_json_errors_and_host_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            with make_server(folder, 0) as server:
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                    client.request('GET', '/')
                    response = client.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertIn(b'Export JSON', response.read())
                    client.request('GET', '/api/report')
                    response = client.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read())['files'], 0)
                    client.request('GET', '/unknown')
                    response = client.getresponse()
                    self.assertEqual(response.status, 404)
                    response.read()
                    client.request('GET', '/api/report', headers={'Host': 'untrusted.example'})
                    response = client.getresponse()
                    self.assertEqual(response.status, 403)
                    response.read()
                    with patch('repolens.web.analyze', side_effect=OSError('private diagnostic')):
                        client.request('GET', '/api/report')
                        response = client.getresponse()
                        self.assertEqual(response.status, 500)
                        self.assertNotIn(b'private diagnostic', response.read())
                    client.close()
                finally:
                    server.shutdown()
                    worker.join(timeout=5)
