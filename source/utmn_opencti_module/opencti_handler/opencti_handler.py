from datetime import datetime, timezone
import ipaddress
import re
import urllib.parse

import requests
from sqlalchemy.orm.attributes import flag_modified

import iris_interface.IrisInterfaceStatus as InterfaceStatus


class OpenCTIClient:
    def __init__(self, base_url, token, verify_tls, proxies, timeout, logger):
        if base_url.endswith('/graphql'):
            self.graphql_url = base_url
            self.base_url = base_url[:-8]
        else:
            self.base_url = base_url.rstrip('/')
            self.graphql_url = f"{self.base_url}/graphql"

        self.token = token
        self.verify_tls = verify_tls
        self.proxies = proxies
        self.timeout = timeout
        self.log = logger

    def graphql(self, query, variables):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(
                self.graphql_url,
                json={"query": query, "variables": variables},
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
                proxies=self.proxies
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            return None, [str(exc)]

        return payload.get('data'), payload.get('errors')


class OpenCTIHandler:
    OBSERVABLES_QUERY_MIN = (
        "query Observables($search: String, $first: Int) {"
        " stixCyberObservables(search: $search, first: $first) {"
        "  edges { node { id entity_type standard_id observable_value } }"
        " }"
        "}"
    )

    INDICATORS_QUERY_MIN = (
        "query Indicators($search: String, $first: Int) {"
        " indicators(search: $search, first: $first) {"
        "  edges { node { id entity_type standard_id name pattern pattern_type } }"
        " }"
        "}"
    )

    OBSERVABLES_QUERY_RICH = (
        "query Observables($search: String, $first: Int) {"
        " stixCyberObservables(search: $search, first: $first) {"
        "  edges { node { id entity_type standard_id observable_value description "
        "  created_at updated_at confidence x_opencti_score } }"
        " }"
        "}"
    )

    INDICATORS_QUERY_RICH = (
        "query Indicators($search: String, $first: Int) {"
        " indicators(search: $search, first: $first) {"
        "  edges { node { id entity_type standard_id name description pattern pattern_type created_at updated_at "
        "  confidence x_opencti_score } }"
        " }"
        "}"
    )


    RELATIONS_QUERY_MIN = (
        "query Relations($fromId: [String], $toId: [String], $first: Int) {"
        " stixCoreRelationships(fromId: $fromId, toId: $toId, first: $first) {"
        "  edges { node { id relationship_type "
        "   from { "
        "    ... on BasicObject { id entity_type } "
        "    ... on StixObject { id entity_type } "
        "    ... on StixCoreObject { id entity_type } "
        "    ... on StixDomainObject { id entity_type } "
        "    ... on StixCyberObservable { id entity_type } "
        "   } "
        "   to { "
        "    ... on BasicObject { id entity_type } "
        "    ... on StixObject { id entity_type } "
        "    ... on StixCoreObject { id entity_type } "
        "    ... on StixDomainObject { id entity_type } "
        "    ... on StixCyberObservable { id entity_type } "
        "   } "
        "  } }"
        " }"
        "}"
    )

    RELATIONS_QUERY_RICH = (
        "query Relations($fromId: [String], $toId: [String], $first: Int) {"
        " stixCoreRelationships(fromId: $fromId, toId: $toId, first: $first) {"
        "  edges { node { id relationship_type "
        "   from { "
        "    ... on BasicObject { id entity_type } "
        "    ... on StixObject { id entity_type } "
        "    ... on StixCoreObject { id entity_type } "
        "    ... on StixDomainObject { id entity_type name description } "
        "    ... on StixCyberObservable { id entity_type observable_value value } "
        "   } "
        "   to { "
        "    ... on BasicObject { id entity_type } "
        "    ... on StixObject { id entity_type } "
        "    ... on StixCoreObject { id entity_type } "
        "    ... on StixDomainObject { id entity_type name description } "
        "    ... on StixCyberObservable { id entity_type observable_value value } "
        "   } "
        "  } }"
        " }"
        "}"
    )

    def __init__(self, mod_config, server_config, logger):
        self.mod_config = mod_config or {}
        self.server_config = server_config or {}
        self.log = logger
        self.client = self._build_client()

    def _build_client(self):
        base_url = (self.mod_config.get('opencti_url') or '').strip()
        token = (self.mod_config.get('opencti_token') or '').strip()

        if not base_url or not token:
            self.log.error('OpenCTI URL or token missing in configuration')
            return None

        verify_tls = bool(self.mod_config.get('opencti_verify_tls', True))
        timeout = int(self.mod_config.get('opencti_timeout', 30))

        proxies = None
        if self.mod_config.get('opencti_use_proxy'):
            http_proxy = self.server_config.get('http_proxy')
            https_proxy = self.server_config.get('https_proxy')
            if http_proxy or https_proxy:
                proxies = {}
                if http_proxy:
                    proxies['http'] = http_proxy
                if https_proxy:
                    proxies['https'] = https_proxy

        return OpenCTIClient(
            base_url=base_url,
            token=token,
            verify_tls=verify_tls,
            proxies=proxies,
            timeout=timeout,
            logger=self.log
        )

    def _allowlisted(self, type_name):
        allowlist = self.mod_config.get('opencti_ioc_type_allowlist', '')
        allowlist = {item.strip().lower() for item in allowlist.split(',') if item.strip()}
        if not allowlist or 'all' in allowlist:
            return True

        kind = self._ioc_kind(type_name)
        return kind in allowlist

    @staticmethod
    def _ioc_kind(type_name):
        if not type_name:
            return 'other'

        lowered = type_name.lower()
        if 'ip' in lowered:
            return 'ip'
        if 'domain' in lowered or 'hostname' in lowered:
            return 'domain'
        if 'url' in lowered:
            return 'url'
        if 'md5' in lowered or 'sha' in lowered or 'hash' in lowered:
            return 'hash'
        if 'email' in lowered:
            return 'email'
        return 'other'

    def _get_match_mode(self):
        mode = (self.mod_config.get('opencti_match_mode') or 'fuzzy')
        if not isinstance(mode, str):
            return 'fuzzy'
        mode = mode.strip().lower()
        if mode not in ('fuzzy', 'exact', 'hybrid'):
            return 'fuzzy'
        return mode

    def _defang_enabled(self):
        return bool(self.mod_config.get('opencti_defang_enabled', True))

    def _normalize_urls_enabled(self):
        return bool(self.mod_config.get('opencti_normalize_urls', True))

    @staticmethod
    def _defang_value(value):
        if not isinstance(value, str):
            return value
        updated = re.sub(r'(?i)^hxxps://', 'https://', value)
        updated = re.sub(r'(?i)^hxxp://', 'http://', updated)
        updated = updated.replace('[.]', '.')
        updated = updated.replace('(.)', '.')
        updated = updated.replace('[:]', ':')
        return updated

    @staticmethod
    def _normalize_ip(value):
        if not value:
            return ''
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            parts = value.split('.')
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                try:
                    numbers = [int(part) for part in parts]
                except ValueError:
                    return ''
                if all(0 <= num <= 255 for num in numbers):
                    return '.'.join(str(num) for num in numbers)
            return ''

    def _normalize_url(self, value):
        try:
            parts = urllib.parse.urlsplit(value)
        except Exception:
            return value

        scheme = parts.scheme.lower()
        netloc = parts.netloc
        if not scheme or not netloc:
            return value.lower()

        userinfo, _, hostport = netloc.rpartition('@')
        host = hostport
        port = ''
        if ':' in hostport:
            host, port = hostport.rsplit(':', 1)
        host = host.lower()

        if port:
            if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
                port = ''

        netloc = f"{userinfo}@{host}" if userinfo else host
        if port:
            netloc = f"{netloc}:{port}"

        path = parts.path or ''
        if path == '/':
            path = ''

        return urllib.parse.urlunsplit((scheme, netloc, path, parts.query, parts.fragment))

    def _normalize_value(self, value, kind, defang=True):
        if value is None:
            return ''
        if isinstance(value, (int, float)):
            value = str(value)
        if not isinstance(value, str):
            return ''
        value = value.strip()
        if not value:
            return ''
        if defang and self._defang_enabled() and kind in ('ip', 'domain', 'url', 'hash', 'email'):
            value = self._defang_value(value)

        if kind == 'ip':
            return self._normalize_ip(value)
        if kind == 'domain':
            return value.lower().rstrip('.')
        if kind == 'hash':
            return value.strip().lower()
        if kind == 'email':
            return value.lower()
        if kind == 'url':
            if self._normalize_urls_enabled():
                return self._normalize_url(value)
            return value
        return value

    @staticmethod
    def _extract_pattern_literals(pattern):
        if not pattern or not isinstance(pattern, str):
            return []
        literals = []
        for regex in (r"'([^'\\]*(?:\\.[^'\\]*)*)'", r'"([^"\\]*(?:\\.[^"\\]*)*)"'):
            for match in re.finditer(regex, pattern):
                literal = match.group(1)
                if '\\' in literal:
                    literal = re.sub(r'\\(.)', r'\1', literal)
                literals.append(literal)
        return literals

    def _observable_match_details(self, node, target_value, kind):
        if not isinstance(node, dict):
            return []
        matched_fields = []
        for key in ('observable_value', 'value', 'name'):
            value = node.get(key)
            if value is None:
                continue
            if isinstance(value, (int, float)):
                value = str(value)
            if not isinstance(value, str):
                continue
            candidate_value = self._normalize_value(value, kind, defang=True)
            if candidate_value and candidate_value == target_value:
                matched_fields.append(key)
        return matched_fields

    def _indicator_match_details(self, node, target_value, kind):
        if not isinstance(node, dict):
            return []
        pattern = node.get('pattern')
        matched_literals = []
        for literal in self._extract_pattern_literals(pattern):
            candidate_value = self._normalize_value(literal, kind, defang=True)
            if candidate_value and candidate_value == target_value:
                matched_literals.append(literal)
        return matched_literals

    def _filter_exact_matches(self, nodes, ioc_value, ioc_type_name, matcher, detail_key):
        kind = self._ioc_kind(ioc_type_name)
        target_value = self._normalize_value(ioc_value, kind, defang=True)
        if not target_value:
            return []
        matched = []
        for node in nodes or []:
            details = matcher(node, target_value, kind)
            if details:
                matched.append({
                    "node": node,
                    detail_key: details
                })
        return matched


    def _query(self, query, variables, fallback_query=None):
        if not self.client:
            return None, ['OpenCTI client not initialized']

        data, errors = self.client.graphql(query=query, variables=variables)
        if errors and fallback_query:
            self.log.warning('OpenCTI query failed, retrying with minimal query')
            data, errors = self.client.graphql(query=fallback_query, variables=variables)

        return data, errors

    @staticmethod
    def _extract_nodes(data, root_key):
        if not data or not data.get(root_key):
            return []

        edges = data.get(root_key, {}).get('edges') or []
        nodes = []
        for edge in edges:
            node = edge.get('node') if isinstance(edge, dict) else None
            if node:
                nodes.append(node)
        return nodes

    def _search_observables(self, search_value, max_results):
        rich = bool(self.mod_config.get('opencti_rich_query_enabled'))
        query = self.OBSERVABLES_QUERY_RICH if rich else self.OBSERVABLES_QUERY_MIN
        fallback = self.OBSERVABLES_QUERY_MIN if rich else None

        data, errors = self._query(query, {"search": search_value, "first": max_results}, fallback_query=fallback)
        nodes = self._extract_nodes(data, 'stixCyberObservables')
        return {
            "count": len(nodes),
            "nodes": nodes,
            "errors": errors
        }

    def _search_indicators(self, search_value, max_results):
        rich = bool(self.mod_config.get('opencti_rich_query_enabled'))
        query = self.INDICATORS_QUERY_RICH if rich else self.INDICATORS_QUERY_MIN
        fallback = self.INDICATORS_QUERY_MIN if rich else None

        data, errors = self._query(query, {"search": search_value, "first": max_results}, fallback_query=fallback)
        nodes = self._extract_nodes(data, 'indicators')
        return {
            "count": len(nodes),
            "nodes": nodes,
            "errors": errors
        }

    def enrich_alert(self, alert):
        if not alert:
            return InterfaceStatus.I2Error(message='Empty alert')

        if not self.client:
            self.log.warning('OpenCTI client not configured - skipping enrichment')
            return InterfaceStatus.I2Success(message='OpenCTI not configured; skipped')

        iocs = self._safe_get_iocs(alert)
        if not iocs:
            return InterfaceStatus.I2Success(message='Alert has no IOCs')

        max_iocs = int(self.mod_config.get('opencti_max_iocs_per_alert', 100))
        iocs = iocs[:max_iocs]

        in_status = InterfaceStatus.IIStatus(code=InterfaceStatus.I2CodeNoError)
        seen = set()

        for ioc in iocs:
            ioc_value = getattr(ioc, 'ioc_value', None)
            ioc_type_name = None
            try:
                ioc_type = getattr(ioc, 'ioc_type', None)
                if ioc_type:
                    ioc_type_name = ioc_type.type_name
            except Exception as exc:
                self.log.error(f'Failed to resolve IOC type for {ioc_value}: {exc}')

            if not ioc_value:
                continue

            dedup_key = (ioc_value, ioc_type_name)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            if not self._allowlisted(ioc_type_name):
                self.log.info(f'Skipping IOC type {ioc_type_name} for {ioc_value}')
                continue

            status = self._enrich_ioc(ioc, ioc_value, ioc_type_name, alert)
            in_status = InterfaceStatus.merge_status(in_status, status)

        return in_status

    def enrich_ioc(self, ioc):
        if not ioc:
            return InterfaceStatus.I2Error(message='Empty IOC')

        if not self.client:
            self.log.warning('OpenCTI client not configured - skipping enrichment')
            return InterfaceStatus.I2Success(message='OpenCTI not configured; skipped')


        ioc_value = getattr(ioc, 'ioc_value', None)
        ioc_type_name = None
        try:
            ioc_type = getattr(ioc, 'ioc_type', None)
            if ioc_type:
                ioc_type_name = ioc_type.type_name
        except Exception as exc:
            self.log.error(f'Failed to resolve IOC type for {ioc_value}: {exc}')

        if not ioc_value:
            return InterfaceStatus.I2Success(message='IOC has no value')

        if not self._allowlisted(ioc_type_name):
            self.log.info(f'Skipping IOC type {ioc_type_name} for {ioc_value}')
            return InterfaceStatus.I2Success(message='IOC type not allowlisted')

        return self._enrich_ioc(ioc, ioc_value, ioc_type_name, alert=None)

    def _safe_get_iocs(self, alert):
        try:
            return list(getattr(alert, 'iocs', []) or [])
        except Exception as exc:
            self.log.error(f'Failed to load alert IOCs, retrying with fresh session: {exc}')
            try:
                from app import db
                from app.models import Ioc
                from app.models.alerts import Alert
                from sqlalchemy.orm import selectinload

                alert_id = getattr(alert, 'alert_id', None)
                if alert_id is None:
                    return []

                fresh = (db.session.query(Alert)
                         .options(selectinload(Alert.iocs).selectinload(Ioc.ioc_type))
                         .filter(Alert.alert_id == alert_id)
                         .first())
                if not fresh:
                    return []
                return list(getattr(fresh, 'iocs', []) or [])
            except Exception as retry_exc:
                self.log.error(f'Failed to reload alert IOCs: {retry_exc}')
                return []

    def _enrich_ioc(self, ioc, ioc_value, ioc_type_name, alert):
        try:
            max_results = int(self.mod_config.get('opencti_max_results', 5))
            store_raw = bool(self.mod_config.get('opencti_store_raw_response'))
            match_mode = self._get_match_mode()
            ioc_kind = self._ioc_kind(ioc_type_name)

            match_input = ioc_value if isinstance(ioc_value, str) else str(ioc_value)
            search_value = match_input.strip()
            should_defang = match_mode in ('exact', 'hybrid')
            if should_defang and self._defang_enabled():
                if ioc_kind in ('ip', 'domain', 'url', 'hash', 'email'):
                    search_value = self._defang_value(search_value)

            normalized_value = self._normalize_value(match_input, ioc_kind, defang=should_defang)
            defanged = bool(should_defang and self._defang_enabled())

            enrichment = {
                "schema_version": "2.1",
                "meta": {
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "source": {
                        "opencti_url": self.client.base_url if self.client else None
                    },
                    "ioc": {
                        "value": match_input,
                        "type": ioc_type_name,
                        "kind": ioc_kind,
                        "normalized": normalized_value,
                        "match_mode": match_mode,
                        "defanged": defanged
                    }
                },
                "results": {
                    "observables": {
                        "raw_count": 0,
                        "matched_count": 0,
                        "matched": []
                    },
                    "indicators": {
                        "raw_count": 0,
                        "matched_count": 0,
                        "matched": []
                    }
                },
                "errors": []
            }

            errors = []

            if self.mod_config.get('opencti_observable_search_enabled'):
                observables = self._search_observables(search_value, max_results)
                raw_nodes = observables.get('nodes') or []
                raw_count = observables.get('count', len(raw_nodes))
                if match_mode in ('exact', 'hybrid'):
                    matched = self._filter_exact_matches(
                        raw_nodes, match_input, ioc_type_name, self._observable_match_details, "matched_fields"
                    )
                else:
                    matched = [{"node": node, "matched_fields": []} for node in raw_nodes]

                enrichment["results"]["observables"] = {
                    "raw_count": raw_count,
                    "matched_count": len(matched),
                    "matched": matched
                }

                if observables.get('errors'):
                    errors.extend(observables.get('errors'))
                if store_raw:
                    enrichment["results"]["observables"]["raw"] = {
                        "count": raw_count,
                        "nodes": raw_nodes,
                        "errors": observables.get('errors')
                    }

            if self.mod_config.get('opencti_indicator_search_enabled'):
                indicators = self._search_indicators(search_value, max_results)
                raw_nodes = indicators.get('nodes') or []
                raw_count = indicators.get('count', len(raw_nodes))
                if match_mode in ('exact', 'hybrid'):
                    matched = self._filter_exact_matches(
                        raw_nodes, match_input, ioc_type_name, self._indicator_match_details, "matched_literals"
                    )
                else:
                    matched = [{"node": node, "matched_literals": []} for node in raw_nodes]

                enrichment["results"]["indicators"] = {
                    "raw_count": raw_count,
                    "matched_count": len(matched),
                    "matched": matched
                }

                if indicators.get('errors'):
                    errors.extend(indicators.get('errors'))
                if store_raw:
                    enrichment["results"]["indicators"]["raw"] = {
                        "count": raw_count,
                        "nodes": raw_nodes,
                        "errors": indicators.get('errors')
                    }

            if errors:
                enrichment['errors'] = errors

            if match_mode in ('exact', 'hybrid'):
                raw_total = (enrichment["results"]["observables"]["raw_count"] +
                             enrichment["results"]["indicators"]["raw_count"])
                matched_total = (enrichment["results"]["observables"]["matched_count"] +
                                 enrichment["results"]["indicators"]["matched_count"])
                if raw_total > 0 and matched_total == 0:
                    self.log.info(
                        'OpenCTI exact match yielded no results for %s (%s). Raw=%s',
                        match_input, ioc_type_name, raw_total
                    )

            relations = self._build_relations(enrichment)
            if relations is not None:
                enrichment['relations'] = relations

            self._store_enrichment(ioc, enrichment)
            return InterfaceStatus.I2Success(message='Enriched IOC')


        except Exception as exc:
            self.log.exception(exc)
            match_mode = self._get_match_mode()
            ioc_kind = self._ioc_kind(ioc_type_name)
            match_input = ioc_value if isinstance(ioc_value, str) else str(ioc_value)
            should_defang = match_mode in ('exact', 'hybrid')
            normalized_value = self._normalize_value(match_input, ioc_kind, defang=should_defang)
            defanged = bool(should_defang and self._defang_enabled())
            err_payload = {
                "schema_version": "2.1",
                "meta": {
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "source": {
                        "opencti_url": self.client.base_url if self.client else None
                    },
                    "ioc": {
                        "value": match_input,
                        "type": ioc_type_name,
                        "kind": ioc_kind,
                        "normalized": normalized_value,
                        "match_mode": match_mode,
                        "defanged": defanged
                    }
                },
                "results": {
                    "observables": {
                        "raw_count": 0,
                        "matched_count": 0,
                        "matched": []
                    },
                    "indicators": {
                        "raw_count": 0,
                        "matched_count": 0,
                        "matched": []
                    }
                },
                "errors": [str(exc)]
            }
            self._store_enrichment(ioc, err_payload)
            return InterfaceStatus.I2Error(message=str(exc))

    def _store_enrichment(self, ioc, payload):
        current = getattr(ioc, 'ioc_enrichment', None)
        if not isinstance(current, dict):
            current = {} if current is None else {"_raw": current}

        current['opencti'] = payload
        ioc.ioc_enrichment = current
        flag_modified(ioc, 'ioc_enrichment')

    def _build_relations(self, enrichment):
        if not self.mod_config.get('opencti_relations_enabled', True):
            return None

        entities_max = int(self.mod_config.get('opencti_relations_entities_max', 3))
        relations_max = int(self.mod_config.get('opencti_relations_max', 20))

        nodes = []
        try:
            results = enrichment.get('results', {})
            for key in ('indicators', 'observables'):
                section = results.get(key, {})
                matched = section.get('matched') or []
                for item in matched:
                    node = item.get('node') if isinstance(item, dict) else None
                    if node:
                        nodes.append(node)
        except Exception:
            nodes = []

        if not nodes:
            return {"count": 0, "items": []}

        nodes = nodes[:entities_max]
        relations = []
        seen = set()
        errors = []

        for node in nodes:
            node_id = node.get('id') if isinstance(node, dict) else None
            if not node_id:
                continue
            rels, rel_errs = self._fetch_relations(node_id, relations_max)
            if rel_errs:
                errors.extend(rel_errs)
            for rel in rels:
                key = (rel.get('relationship_type'),
                       rel.get('from', {}).get('id'),
                       rel.get('to', {}).get('id'))
                if key in seen:
                    continue
                seen.add(key)
                relations.append(rel)

        output = {"count": len(relations), "items": relations}
        if errors:
            output["errors"] = errors
        return output

    def _fetch_relations(self, node_id, relations_max):
        if not self.client:
            return [], ['OpenCTI client not initialized']

        rich = bool(self.mod_config.get('opencti_rich_query_enabled'))
        query = self.RELATIONS_QUERY_RICH if rich else self.RELATIONS_QUERY_MIN
        fallback = self.RELATIONS_QUERY_MIN if rich else None

        relations = []
        errors = []

        for direction in ('fromId', 'toId'):
            variables = {
                "fromId": [node_id] if direction == 'fromId' else None,
                "toId": [node_id] if direction == 'toId' else None,
                "first": relations_max
            }
            data, errs = self._query(query, variables, fallback_query=fallback)
            if errs:
                errors.extend(errs)
            nodes = self._extract_nodes(data, 'stixCoreRelationships')
            for rel in nodes:
                relations.append(rel)

        return relations, errors
