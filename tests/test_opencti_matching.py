import logging
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'source'))

from utmn_opencti_module.opencti_handler.opencti_handler import OpenCTIHandler


class DummyIoc:
    def __init__(self):
        self.ioc_enrichment = None


class TestOpenCTIHandler(OpenCTIHandler):
    def _build_client(self):
        return None

    def _store_enrichment(self, ioc, payload):
        current = getattr(ioc, 'ioc_enrichment', None)
        if not isinstance(current, dict):
            current = {} if current is None else {"_raw": current}
        current['opencti'] = payload
        ioc.ioc_enrichment = current

    def _search_observables(self, search_value, max_results):
        nodes = [
            {'observable_value': 'evil.com', 'entity_type': 'Domain-Name'},
            {'observable_value': 'sub.evil.com', 'entity_type': 'Domain-Name'}
        ]
        return {
            "count": len(nodes),
            "nodes": nodes,
            "errors": []
        }

    def _search_indicators(self, search_value, max_results):
        nodes = [
            {'pattern': "[domain-name:value = 'evil.com']", 'entity_type': 'Indicator'}
        ]
        return {
            "count": len(nodes),
            "nodes": nodes,
            "errors": []
        }


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

    def test_observable_match_details(self):
        node = {
            'observable_value': 'evil.com',
            'value': 'sub.evil.com'
        }
        target = self.handler._normalize_value('evil.com', 'domain', defang=True)
        details = self.handler._observable_match_details(node, target, 'domain')
        self.assertEqual(['observable_value'], details)

    def test_indicator_match_details(self):
        node = {'pattern': "[domain-name:value = 'evil.com']"}
        target = self.handler._normalize_value('evil.com', 'domain', defang=True)
        details = self.handler._indicator_match_details(node, target, 'domain')
        self.assertEqual(['evil.com'], details)

    def test_filter_exact_matches_domain(self):
        nodes = [
            {'observable_value': 'evil.com'},
            {'observable_value': 'sub.evil.com'}
        ]
        matched = self.handler._filter_exact_matches(
            nodes,
            'evil.com',
            'domain',
            self.handler._observable_match_details,
            'matched_fields'
        )
        self.assertEqual(1, len(matched))
        self.assertEqual('evil.com', matched[0]['node']['observable_value'])
        self.assertEqual(['observable_value'], matched[0]['matched_fields'])

    def test_enrichment_format_counts(self):
        handler = TestOpenCTIHandler(
            mod_config={
                'opencti_defang_enabled': True,
                'opencti_normalize_urls': True,
                'opencti_match_mode': 'exact',
                'opencti_observable_search_enabled': True,
                'opencti_indicator_search_enabled': True,
                'opencti_relations_enabled': False
            },
            server_config={},
            logger=logging.getLogger(__name__)
        )
        ioc = DummyIoc()
        handler._enrich_ioc(ioc, 'evil.com', 'domain', None)
        opencti = ioc.ioc_enrichment.get('opencti')
        self.assertEqual('2.1', opencti.get('schema_version'))
        observables = opencti['results']['observables']
        indicators = opencti['results']['indicators']
        self.assertEqual(2, observables['raw_count'])
        self.assertEqual(1, observables['matched_count'])
        self.assertEqual(1, indicators['raw_count'])
        self.assertEqual(1, indicators['matched_count'])


if __name__ == '__main__':
    unittest.main()
