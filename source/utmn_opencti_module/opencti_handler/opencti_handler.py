from datetime import datetime, timezone

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
        "  edges { node { id entity_type standard_id } }"
        " }"
        "}"
    )

    INDICATORS_QUERY_MIN = (
        "query Indicators($search: String, $first: Int) {"
        " indicators(search: $search, first: $first) {"
        "  edges { node { id entity_type standard_id } }"
        " }"
        "}"
    )

    OBSERVABLES_QUERY_RICH = (
        "query Observables($search: String, $first: Int) {"
        " stixCyberObservables(search: $search, first: $first) {"
        "  edges { node { id entity_type standard_id observable_value value name description "
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

    def _search_observables(self, ioc_value, max_results):
        rich = bool(self.mod_config.get('opencti_rich_query_enabled'))
        query = self.OBSERVABLES_QUERY_RICH if rich else self.OBSERVABLES_QUERY_MIN
        fallback = self.OBSERVABLES_QUERY_MIN if rich else None

        data, errors = self._query(query, {"search": ioc_value, "first": max_results}, fallback_query=fallback)
        nodes = self._extract_nodes(data, 'stixCyberObservables')
        return {
            "count": len(nodes),
            "nodes": nodes,
            "errors": errors
        }

    def _search_indicators(self, ioc_value, max_results):
        rich = bool(self.mod_config.get('opencti_rich_query_enabled'))
        query = self.INDICATORS_QUERY_RICH if rich else self.INDICATORS_QUERY_MIN
        fallback = self.INDICATORS_QUERY_MIN if rich else None

        data, errors = self._query(query, {"search": ioc_value, "first": max_results}, fallback_query=fallback)
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

            enrichment = {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "search_value": ioc_value,
                "ioc_type": ioc_type_name,
                "alert_id": getattr(alert, 'alert_id', None) if alert else None,
                "alert_uuid": str(getattr(alert, 'alert_uuid', '')) if alert and getattr(alert, 'alert_uuid', None) else None,
                "source": {
                    "opencti_url": self.client.base_url if self.client else None
                }
            }

            errors = []

            if self.mod_config.get('opencti_observable_search_enabled'):
                observables = self._search_observables(ioc_value, max_results)
                enrichment["observables"] = {
                    "count": observables.get('count'),
                    "nodes": observables.get('nodes')
                }
                if observables.get('errors'):
                    errors.extend(observables.get('errors'))
                if store_raw:
                    enrichment["observables_raw"] = observables

            if self.mod_config.get('opencti_indicator_search_enabled'):
                indicators = self._search_indicators(ioc_value, max_results)
                enrichment["indicators"] = {
                    "count": indicators.get('count'),
                    "nodes": indicators.get('nodes')
                }
                if indicators.get('errors'):
                    errors.extend(indicators.get('errors'))
                if store_raw:
                    enrichment["indicators_raw"] = indicators

            if errors:
                enrichment['errors'] = errors

            relations = self._build_relations(enrichment)
            if relations is not None:
                enrichment['relations'] = relations

            self._store_enrichment(ioc, enrichment)
            return InterfaceStatus.I2Success(message='Enriched IOC')


        except Exception as exc:
            self.log.exception(exc)
            err_payload = {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "search_value": ioc_value,
                "ioc_type": ioc_type_name,
                "error": str(exc)
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
            if enrichment.get('indicators') and enrichment['indicators'].get('nodes'):
                nodes.extend(enrichment['indicators']['nodes'])
            if enrichment.get('observables') and enrichment['observables'].get('nodes'):
                nodes.extend(enrichment['observables']['nodes'])
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
