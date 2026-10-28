"""Synthetic input contracts and CLI failure behavior; no research data writes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from log_analyzer.zeek_parser import ZeekParseError, parse_zeek
from log_analyzer.windows_v07 import normalize_windows_event
from log_analyzer.linux_ssh_v07 import normalize_linux_ssh_line
from log_analyzer.schema_v07 import validate_event
from log_analyzer.correlation import parse_timestamp

class InputContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'conn.log'
        self.raw = {'ts': 1760000000.25, 'id.orig_p': 50000, 'id.resp_p': 445}
        self.windows = {'EventID': 4625, 'TimeCreated': '2026-10-10T08:00:00Z',
                        'Computer': 'SYNTHETIC', 'Channel': 'Security', 'EventRecordID': 1,
                        'EventData': {'IpAddress': '192.0.2.1', 'IpPort': 50000,
                                      'TargetUserName': 'synthetic', 'LogonType': 3}}

    def parse(self, **changes):
        raw = {**self.raw, **changes}
        self.path.write_text(json.dumps(raw), encoding='utf-8')
        return list(parse_zeek(self.path))[0]

    def test_boolean_timestamps_rejected(self):
        for value in (True, False):
            with self.subTest(value=value), self.assertRaisesRegex(ZeekParseError, 'invalid timestamp'):
                self.parse(ts=value)

    def test_other_invalid_timestamps(self):
        for value in (None, [], {}, 'true', 'NaN', 'Infinity', 1e300):
            with self.subTest(value=value), self.assertRaises(ZeekParseError):
                self.parse(ts=value)

    def test_numeric_timestamp_contract(self):
        for value in (1760000000, 1760000000.25, '1760000000.25', 0):
            with self.subTest(value=value):
                self.assertTrue(self.parse(ts=value)['timestamp_utc'].endswith('Z'))

    def test_fractional_ports_rejected(self):
        for field in ('id.orig_p', 'id.resp_p'):
            for value in (445.9, 445.0, '445.9', '445.0'):
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ZeekParseError, 'invalid port'):
                    self.parse(**{field: value})

    def test_boolean_ports_rejected(self):
        for field in ('id.orig_p', 'id.resp_p'):
            for value in (True, False):
                with self.subTest(field=field, value=value), self.assertRaises(ZeekParseError):
                    self.parse(**{field: value})

    def test_invalid_ports_rejected(self):
        for value in (-1, 65536, 'bad', [], {}, float('inf'), float('nan')):
            with self.subTest(value=value), self.assertRaises(ZeekParseError):
                self.parse(**{'id.resp_p': value})

    def test_integer_port_boundaries(self):
        for value in (0, 1, 445, 65535, '0', '445', '65535'):
            with self.subTest(value=value):
                self.assertEqual(self.parse(**{'id.resp_p': value})['destination']['port'], int(value))

    def test_absent_ports_remain_unknown(self):
        for value in (None, ''):
            self.assertIsNone(self.parse(**{'id.resp_p': value})['destination']['port'])

    def test_ascii_integer_and_unset(self):
        self.path.write_text('#separator \\x09\n#fields\tts\tid.orig_p\tid.resp_p\n1760000000.25\t-\t445\n')
        event = list(parse_zeek(self.path))[0]
        self.assertIsNone(event['source']['port'])
        self.assertEqual(event['destination']['port'], 445)

    def test_invalid_encoding_library_error(self):
        self.path.write_bytes(b'\xff\xfe')
        with self.assertRaisesRegex(ZeekParseError, 'UTF-8'):
            list(parse_zeek(self.path))

    def cli(self, content):
        self.path.write_bytes(content)
        output = self.path.parent / 'output.jsonl'
        output.write_bytes(b'existing output')
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, '-m', 'log_analyzer.zeek_parser',
                                 str(self.path), '--output', str(output)],
                                env={**os.environ, 'PYTHONPATH': str(ROOT / 'src'),
                                     'PYTHONDONTWRITEBYTECODE': '1'},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('ERROR:', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), digest)
        self.assertEqual(output.read_bytes(), b'existing output')
        return result

    def test_invalid_encoding_cli_preserves_files(self):
        result = self.cli(b'\xff')
        self.assertIn('UTF-8', result.stderr)
        self.assertIn('conn.log', result.stderr)

    def test_boolean_timestamp_cli(self):
        self.cli(json.dumps({**self.raw, 'ts': True}).encode())

    def test_fractional_port_cli(self):
        self.cli(json.dumps({**self.raw, 'id.resp_p': 445.9}).encode())

    def test_windows_contract_already_strict(self):
        for field, value in (('TimeCreated', True), ('TimeCreated', False),
                             ('IpPort', True), ('IpPort', 445.9), ('IpPort', 445.0)):
            raw = copy.deepcopy(self.windows)
            if field == 'IpPort': raw['EventData'][field] = value
            else: raw[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                normalize_windows_event(raw, filename='synthetic', line_number=1)

    def test_linux_contract_already_strict_at_public_entry(self):
        for stamp, port in (('True', '50000'), ('False', '50000'),
                            ('2026-10-10T08:00:00Z', '445.9')):
            line = f'{stamp} lab sshd[1]: Failed password for synthetic from 192.0.2.1 port {port} ssh2'
            with self.subTest(line=line), self.assertRaises(ValueError):
                normalize_linux_ssh_line(line, filename='synthetic', line_number=1)

    def test_normalized_schema_and_correlation_contract(self):
        event = normalize_windows_event(self.windows, filename='synthetic', line_number=1)
        for stamp in (True, False):
            changed = {**event, 'timestamp_utc': stamp}
            self.assertFalse(validate_event(changed)['valid'])
            with self.assertRaises(ValueError): parse_timestamp(stamp)
        for value in (True, 445.9, 445.0):
            changed = copy.deepcopy(event)
            changed['source']['port'] = value
            self.assertFalse(validate_event(changed)['valid'])
