import logging
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'source'))

from utmn_opencti_module.opencti_handler.opencti_handler import OpenCTIHandler


class OpenCTIMatchingTests(unittest.TestCase):
    def setUp(self):
        self.handler = OpenCTIHandler(
            mod_config={
                'opencti_defang_enabled': True,
                'opencti_normalize_urls': True,
                'opencti_match_mode': 'exact'
            },
            server_config={},
            logger=logging.getLogger(__name__)
        )

    def test_defang_value(self):
        value = 'hxxp://evil[.]com'
        self.assertEqual('http://evil.com', self.handler._defang_value(value))

    def test_normalize_ip(self):
        value = '001.002.003.004'
        normalized = self.handler._normalize_value(value, 'ip')
        self.assertEqual('1.2.3.4', normalized)

    def test_normalize_domain(self):
        value = 'Example.COM.'
        normalized = self.handler._normalize_value(value, 'domain')
        self.assertEqual('example.com', normalized)

    def test_normalize_url(self):
        value = 'HTTP://EXAMPLE.COM:80/a'
        normalized = self.handler._normalize_value(value, 'url')
        self.assertEqual('http://example.com/a', normalized)

    def test_extract_pattern_literals(self):
        pattern = "[domain-name:value = 'evil.com' OR url:value = 'http://evil.com']"
        literals = self.handler._extract_pattern_literals(pattern)
        self.assertEqual(['evil.com', 'http://evil.com'], literals)

    def test_filter_exact_matches_domain(self):
        nodes = [
            {'observable_value': 'evil.com'},
            {'observable_value': 'sub.evil.com'}
        ]
        matched = self.handler._filter_exact_matches(
            nodes,
            'evil.com',
            'domain',
            self.handler._observable_matches
        )
        self.assertEqual(1, len(matched))
        self.assertEqual('evil.com', matched[0]['observable_value'])

    def test_filter_exact_matches_hash(self):
        nodes = [
            {'value': 'ABCDEF1234567890ABCDEF1234567890'},
            {'value': '1234567890ABCDEF1234567890ABCDEF'}
        ]
        matched = self.handler._filter_exact_matches(
            nodes,
            'abcdef1234567890abcdef1234567890',
            'md5',
            self.handler._observable_matches
        )
        self.assertEqual(1, len(matched))
        self.assertEqual('ABCDEF1234567890ABCDEF1234567890', matched[0]['value'])


if __name__ == '__main__':
    unittest.main()
