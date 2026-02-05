#  IRIS Source Code
#  Copyright (C) 2023 - DFIR-IRIS
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
import json
import marshmallow
import re
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from typing import Union, List, Dict, Any, Optional, Tuple
from werkzeug import Response

import app
from app import db
from app.blueprints.case.case_comments import case_comment_update
from app.datamgmt.alerts.alerts_db import get_filtered_alerts, get_alert_by_id, create_case_from_alert, \
    register_related_alerts, delete_related_alerts_cache
from app.datamgmt.alerts.alerts_db import merge_alert_in_case, unmerge_alert_from_case, cache_similar_alert
from app.datamgmt.alerts.alerts_db import get_related_alerts, get_related_alerts_details
from app.datamgmt.alerts.alerts_db import get_alert_comments, delete_alert_comment, get_alert_comment
from app.datamgmt.alerts.alerts_db import delete_similar_alert_cache, delete_alerts
from app.datamgmt.alerts.alerts_db import create_case_from_alerts
from app.datamgmt.case.case_iocs_db import get_ioc_types_list
from app.datamgmt.case.case_db import get_case
from app.datamgmt.manage.manage_access_control_db import check_ua_case_client, user_has_client_access
from app.iris_engine.access_control.utils import ac_set_new_case_access
from app.iris_engine.module_handler.module_handler import call_modules_hook
from app.iris_engine.utils.tracker import track_activity
from app.models.alerts import AlertStatus, AlertSimilarity, Alert
from app.models.authorization import Permissions
from app.schema.marshables import AlertSchema, CaseSchema, CommentSchema, CaseAssetsSchema, IocSchema
from app.util import ac_api_requires
from app.util import response_error, add_obj_history_entry, ac_requires
from app.util import response_success

alerts_blueprint = Blueprint(
    'alerts',
    __name__,
    template_folder='templates'
)

IOC_RAW_FIELDS = [
    "assigned_dst_host",
    "assigned_dst_ip",
    "dst.fqdn",
    "dst.host",
    "dst.hostname",
    "dst.ip",
    "external_dst.fqdn",
    "external_dst.host",
    "external_dst.hostname",
    "external_dst.ip",
    "subject.process.hash",
    "subject.process.hash.imphash",
    "subject.process.hash.md5",
    "subject.process.hash.sha1",
    "subject.process.hash.sha256",
    "subject.process.name",
    "subject.process.parent.hash",
    "subject.process.parent.hash.imphash",
    "subject.process.parent.hash.md5",
    "subject.process.parent.hash.sha1",
    "subject.process.parent.hash.sha256",
    "subject.process.parent.name",
    "object.domain",
    "object.hash",
    "object.hash.imphash",
    "object.hash.md5",
    "object.hash.sha1",
    "object.hash.sha256",
    "object.name",
    "object.process.hash",
    "object.process.hash.imphash",
    "object.process.hash.md5",
    "object.process.hash.sha1",
    "object.process.hash.sha256",
    "object.process.name",
    "object.process.parent.hash",
    "object.process.parent.hash.imphash",
    "object.process.parent.hash.sha1",
    "object.process.parent.hash.md5",
    "object.process.parent.hash.sha256",
    "object.process.parent.name",
    "nas_fqdn",
    "nas_ip",
]

IOC_TYPE_CANDIDATES = {
    "ip": ["ip-any", "ip", "ipv4", "ipv6"],
    "domain": ["domain", "fqdn", "hostname", "host"],
    "filename": ["filename"],
    "md5": ["md5"],
    "sha1": ["sha1"],
    "sha256": ["sha256"],
    "imphash": ["imphash"],
    "hash": ["hash"],
}


def _parse_raw_event(raw_event: Any) -> Optional[Any]:
    if raw_event is None:
        return None
    if isinstance(raw_event, dict):
        return raw_event
    if isinstance(raw_event, list):
        return raw_event
    if isinstance(raw_event, str):
        raw_event = raw_event.strip()
        if not raw_event:
            return None
        try:
            parsed = json.loads(raw_event)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, (dict, list)):
            return parsed
    return None


def _flatten_values(value: Any, key_hint: Optional[str] = None) -> List[Tuple[Any, Optional[str]]]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        flattened: List[Tuple[Any, Optional[str]]] = []
        for item in value:
            flattened.extend(_flatten_values(item, key_hint))
        return flattened
    if isinstance(value, dict):
        flattened: List[Tuple[Any, Optional[str]]] = []
        for key, item in value.items():
            flattened.extend(_flatten_values(item, str(key)))
        return flattened
    return [(value, key_hint)]


def _get_values_at_path(payload: Any, path: str) -> List[Any]:
    collected: List[Any] = []
    if isinstance(payload, dict) and path in payload:
        collected.append(payload[path])
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict) and path in item:
                collected.append(item[path])

    parts = path.split(".")
    nodes: List[Any] = [payload]
    for part in parts:
        next_nodes: List[Any] = []
        for node in nodes:
            if isinstance(node, dict) and part in node:
                next_nodes.append(node[part])
            elif isinstance(node, list):
                for item in node:
                    if isinstance(item, dict) and part in item:
                        next_nodes.append(item[part])
        nodes = next_nodes
        if not nodes:
            break
    collected.extend(nodes)
    return collected


def _infer_hash_type(value: str) -> Optional[str]:
    value = value.strip().lower()
    if ":" in value:
        prefix, rest = value.split(":", 1)
        if prefix in ("md5", "sha1", "sha256", "imphash"):
            return prefix
        value = rest
    if re.fullmatch(r"[0-9a-f]{32}", value):
        return "md5"
    if re.fullmatch(r"[0-9a-f]{40}", value):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{64}", value):
        return "sha256"
    return None


def _extract_labeled_hashes(value: str) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    for match in re.finditer(r"(?i)(imphash|md5|sha1|sha256)[:= ]+([0-9a-f]{32,64})", value):
        label = match.group(1).lower()
        hash_value = match.group(2).lower()
        results.append((label, hash_value))
    return results


def _type_hint_from_path(path: str, key_hint: Optional[str]) -> Optional[str]:
    if key_hint:
        key_hint = key_hint.lower()
        if key_hint in ("md5", "sha1", "sha256", "imphash"):
            return key_hint

    if path.endswith(".md5"):
        return "md5"
    if path.endswith(".sha1"):
        return "sha1"
    if path.endswith(".sha256"):
        return "sha256"
    if path.endswith(".imphash"):
        return "imphash"
    if path.endswith(".ip") or path in ("assigned_dst_ip", "nas_ip"):
        return "ip"
    if path.endswith(".fqdn") or path.endswith(".hostname") or path.endswith(".host"):
        return "domain"
    if path in ("assigned_dst_host", "object.domain", "nas_fqdn"):
        return "domain"
    if path in ("subject.process.name", "subject.process.parent.name",
                "object.process.name", "object.process.parent.name",
                "object.name"):
        return "filename"
    if path.endswith(".hash"):
        return "hash"
    return None


def _resolve_type_id(
    type_hint: Optional[str],
    type_index: Dict[str, int],
    value: str,
    type_validation_by_id: Optional[Dict[int, Optional[str]]] = None
) -> Optional[int]:
    if not type_hint:
        return None
    if type_hint == "hash":
        inferred = _infer_hash_type(value)
        if inferred:
            type_hint = inferred
    candidates = IOC_TYPE_CANDIDATES.get(type_hint, [type_hint])
    for name in candidates:
        type_id = type_index.get(name.lower())
        if type_id is not None:
            if type_validation_by_id:
                regex = type_validation_by_id.get(type_id)
                if regex and not re.fullmatch(regex, value, re.IGNORECASE):
                    continue
            return type_id
    return None


def _build_type_maps() -> Tuple[Dict[str, int], Dict[int, Optional[str]]]:
    type_rows = get_ioc_types_list()
    type_index = {
        row['type_name'].lower(): row['type_id']
        for row in type_rows
        if row.get('type_name') and row.get('type_id') is not None
    }
    type_validation_by_id = {
        row['type_id']: row.get('type_validation_regex')
        for row in type_rows
        if row.get('type_id') is not None
    }
    return type_index, type_validation_by_id


def _sanitize_iocs(
    iocs_list: Optional[List[Dict[str, Any]]],
    type_validation_by_id: Dict[int, Optional[str]]
) -> List[Dict[str, Any]]:
    if not iocs_list:
        return []

    sanitized: List[Dict[str, Any]] = []
    for ioc in iocs_list:
        if not isinstance(ioc, dict):
            continue
        raw_value = ioc.get("ioc_value")
        if raw_value is None:
            continue
        if isinstance(raw_value, (int, float)):
            value = str(raw_value)
        elif isinstance(raw_value, str):
            value = raw_value
        else:
            continue
        value = value.strip()
        if not value:
            continue

        type_id = ioc.get("ioc_type_id")
        valid_type_id: Optional[int] = None
        if type_id is not None:
            try:
                type_id_int = int(type_id)
            except (TypeError, ValueError):
                type_id_int = None
            if type_id_int is not None and type_id_int in type_validation_by_id:
                regex = type_validation_by_id.get(type_id_int)
                if regex:
                    if re.fullmatch(regex, value, re.IGNORECASE):
                        valid_type_id = type_id_int
                else:
                    valid_type_id = type_id_int

        sanitized_ioc = dict(ioc)
        sanitized_ioc["ioc_value"] = value
        if valid_type_id is not None:
            sanitized_ioc["ioc_type_id"] = valid_type_id
        else:
            sanitized_ioc.pop("ioc_type_id", None)
        sanitized.append(sanitized_ioc)

    return sanitized


def _extract_iocs_from_raw(
    raw_event: Any,
    type_index: Dict[str, int],
    type_validation_by_id: Optional[Dict[int, Optional[str]]] = None
) -> List[Dict[str, Any]]:
    payload = _parse_raw_event(raw_event)
    if not payload:
        return []

    if isinstance(payload, list):
        payloads = [item for item in payload if isinstance(item, dict)]
    else:
        payloads = [payload]
        events = payload.get("events") if isinstance(payload, dict) else None
        if isinstance(events, list):
            payloads.extend([item for item in events if isinstance(item, dict)])

    extracted: List[Dict[str, Any]] = []
    seen = set()

    for payload in payloads:
        for path in IOC_RAW_FIELDS:
            values = _get_values_at_path(payload, path)
            for value in values:
                for raw_value, key_hint in _flatten_values(value):
                    if raw_value is None:
                        continue
                    if isinstance(raw_value, (int, float)):
                        value_str = str(raw_value)
                    elif isinstance(raw_value, str):
                        value_str = raw_value.strip()
                    else:
                        continue

                    if not value_str or value_str.lower() in ("null", "none", "unknown", "-"):
                        continue

                    type_hint = _type_hint_from_path(path, key_hint)
                    if type_hint == "hash":
                        parsed = _extract_labeled_hashes(value_str)
                        if parsed:
                            for label, hash_value in parsed:
                                type_id = _resolve_type_id(label, type_index, hash_value, type_validation_by_id)
                                key = (hash_value.lower(), type_id)
                                if key in seen:
                                    continue
                                seen.add(key)
                                extracted.append({
                                    "ioc_value": hash_value,
                                    "ioc_type_id": type_id,
                                })
                            continue

                    type_id = _resolve_type_id(type_hint, type_index, value_str, type_validation_by_id)
                    key = (value_str.lower(), type_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    extracted.append({
                        "ioc_value": value_str,
                        "ioc_type_id": type_id,
                    })

    return extracted


def _merge_iocs(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    by_value: Dict[str, List[Dict[str, Any]]] = {}

    for ioc in existing or []:
        if "ioc_type_id" not in ioc:
            ioc["ioc_type_id"] = None
        value = (ioc.get("ioc_value") or "").strip()
        if not value:
            continue
        value_key = value.lower()
        merged.append(ioc)
        by_value.setdefault(value_key, []).append(ioc)

    for ioc in incoming or []:
        if "ioc_type_id" not in ioc:
            ioc["ioc_type_id"] = None
        value = (ioc.get("ioc_value") or "").strip()
        if not value:
            continue
        value_key = value.lower()
        if value_key in by_value:
            incoming_type = ioc.get("ioc_type_id")
            if incoming_type is not None:
                for existing_ioc in by_value[value_key]:
                    existing_type = existing_ioc.get("ioc_type_id")
                    if existing_type is None or existing_type != incoming_type:
                        existing_ioc["ioc_type_id"] = incoming_type
            continue
        merged.append(ioc)
        by_value.setdefault(value_key, []).append(ioc)

    return merged


@alerts_blueprint.route('/alerts/filter', methods=['GET'])
@ac_api_requires(Permissions.alerts_read)
def alerts_list_route() -> Response:
    """
    Get a list of alerts from the database

    args:
        caseid (str): The case id

    returns:
        Response: The response
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    alert_ids_str = request.args.get('alert_ids')
    alert_ids = None
    if alert_ids_str:
        try:

            if ',' in alert_ids_str:
                alert_ids = [int(alert_id) for alert_id in alert_ids_str.split(',')]

            else:
                alert_ids = [int(alert_ids_str)]

        except ValueError:
            return response_error('Invalid alert id')

    alert_assets_str = request.args.get('alert_assets')
    alert_assets = None
    if alert_assets_str:
        try:

            if ',' in alert_assets_str:
                alert_assets = [str(alert_asset) for alert_asset in alert_assets_str.split(',')]

            else:
                alert_assets = [str(alert_assets_str)]

        except ValueError:
            return response_error('Invalid alert asset')

    alert_iocs_str = request.args.get('alert_iocs')
    alert_iocs = None
    if alert_iocs_str:
        try:

            if ',' in alert_iocs_str:
                alert_iocs = [str(alert_ioc) for alert_ioc in alert_iocs_str.split(',')]

            else:
                alert_iocs = [str(alert_iocs_str)]

        except ValueError:
            return response_error('Invalid alert ioc')

    fields_str = request.args.get('fields')
    if fields_str:
        # Split into a list
        fields = [field.strip() for field in fields_str.split(',') if field.strip()]
    else:
        fields = None

    try:
        filtered_data = get_filtered_alerts(
            start_date=request.args.get('creation_start_date'),
            end_date=request.args.get('creation_end_date'),
            source_start_date=request.args.get('source_start_date'),
            source_end_date=request.args.get('source_end_date'),
            source_reference=request.args.get('source_reference'),
            title=request.args.get('alert_title'),
            description=request.args.get('alert_description'),
            status=request.args.get('alert_status_id', type=int),
            severity=request.args.get('alert_severity_id', type=int),
            owner=request.args.get('alert_owner_id', type=int),
            source=request.args.get('alert_source'),
            tags=request.args.get('alert_tags'),
            classification=request.args.get('alert_classification_id', type=int),
            client=request.args.get('alert_customer_id'),
            case_id=request.args.get('case_id', type=int),
            alert_ids=alert_ids,
            page=page,
            per_page=per_page,
            sort=request.args.get('sort', 'desc', type=str),
            custom_conditions=request.args.get('custom_conditions'),
            assets=alert_assets,
            iocs=alert_iocs,
            resolution_status=request.args.get('alert_resolution_id', type=int),
            current_user_id=current_user.id,
            fields=fields
        )

    except Exception as e:
        app.app.logger.exception(e)
        return response_error(str(e))

    if filtered_data is None:
        return response_error('Filtering error')

    return response_success(data=filtered_data)


@alerts_blueprint.route('/alerts/add', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alerts_add_route() -> Response:
    """
    Add a new alert to the database

    args:
        caseid (str): The case id

    returns:
        Response: The response
    """

    if not request.json:
        return response_error('No JSON data provided')

    alert_schema = AlertSchema()
    ioc_schema = IocSchema()
    asset_schema = CaseAssetsSchema()

    try:
        # Load the JSON data from the request
        data = request.get_json()

        iocs_list = data.pop('alert_iocs', [])
        assets_list = data.pop('alert_assets', [])

        type_index, type_validation_by_id = _build_type_maps()
        iocs_list = _sanitize_iocs(iocs_list, type_validation_by_id)
        raw_event = data.get('alert_source_content')
        extracted_iocs = _extract_iocs_from_raw(raw_event, type_index, type_validation_by_id)
        if _parse_raw_event(raw_event) is not None:
            allowed_values = {
                (ioc.get("ioc_value") or "").strip().lower()
                for ioc in extracted_iocs
                if (ioc.get("ioc_value") or "").strip()
            }
            filtered_iocs = [
                ioc for ioc in iocs_list
                if (ioc.get("ioc_value") or "").strip().lower() in allowed_values
            ]
            iocs_list = _merge_iocs(filtered_iocs, extracted_iocs)
        else:
            iocs_list = _merge_iocs(iocs_list, extracted_iocs)

        iocs = ioc_schema.load(iocs_list, many=True)
        assets = asset_schema.load(assets_list, many=True)

        # Deserialize the JSON data into an Alert object
        new_alert = alert_schema.load(data)

        # Verify the user is entitled to create an alert for the client
        if not user_has_client_access(current_user.id, new_alert.alert_customer_id):
            return response_error('User not entitled to create alerts for the client')

        new_alert.alert_creation_time = datetime.utcnow()

        new_alert.iocs = iocs
        new_alert.assets = assets

        # Add the new alert to the session and commit it
        db.session.add(new_alert)
        db.session.commit()

        # Add history entry
        add_obj_history_entry(new_alert, 'Alert created')

        # Cache the alert for similarities check
        cache_similar_alert(new_alert.alert_customer_id, assets=assets_list,
                            iocs=iocs_list, alert_id=new_alert.alert_id,
                            creation_date=new_alert.alert_source_event_time)

        #register_related_alerts(new_alert, assets_list=assets, iocs_list=iocs)
        
        new_alert = call_modules_hook('on_postload_alert_create', data=new_alert)

        track_activity(f"created alert #{new_alert.alert_id} - {new_alert.alert_title}", ctx_less=True)

        # Emit a socket io event
        app.socket_io.emit('new_alert', json.dumps({
            'alert_id': new_alert.alert_id
        }), namespace='/alerts')

        # Return the newly created alert as JSON
        return response_success(data=alert_schema.dump(new_alert))

    except Exception as e:
        app.app.logger.exception(e)
        # Handle any errors during deserialization or DB operations
        return response_error(str(e))


@alerts_blueprint.route('/alerts/<int:alert_id>', methods=['GET'])
@ac_api_requires(Permissions.alerts_read)
def alerts_get_route(alert_id) -> Response:
    """
    Get an alert from the database

    args:
        caseid (str): The case id
        alert_id (int): The alert id

    returns:
        Response: The response
    """

    alert_schema = AlertSchema()

    # Get the alert from the database
    alert = get_alert_by_id(alert_id)

    # Return the alert as JSON
    if alert is None:
        return response_error('Alert not found')

    if not user_has_client_access(current_user.id, alert.alert_customer_id):
        return response_error('Alert not found')

    alert_dump = alert_schema.dump(alert)

    # Get similar alerts
    similar_alerts = get_related_alerts(alert.alert_customer_id, alert.assets, alert.iocs)
    alert_dump['related_alerts'] = similar_alerts

    return response_success(data=alert_dump)


@alerts_blueprint.route('/alerts/similarities/<int:alert_id>', methods=['GET'])
@ac_api_requires(Permissions.alerts_read)
def alerts_similarities_route(alert_id) -> Response:
    """
    Get an alert and similarities from the database

    args:
        caseid (str): The case id
        alert_id (int): The alert id

    returns:
        Response: The response
    """

    # Get the alert from the database
    alert = get_alert_by_id(alert_id)

    # Return the alert as JSON
    if alert is None:
        return response_error('Alert not found')

    if not user_has_client_access(current_user.id, alert.alert_customer_id):
        return response_error('Alert not found')

    open_alerts = request.args.get('open-alerts', 'false').lower() == 'true'
    open_cases = request.args.get('open-cases', 'false').lower() == 'true'
    closed_cases = request.args.get('closed-cases', 'false').lower() == 'true'
    closed_alerts = request.args.get('closed-alerts', 'false').lower() == 'true'
    days_back = request.args.get('days-back', 180, type=int)
    number_of_results = request.args.get('number-of-nodes', 100, type=int)

    if number_of_results < 0:
        number_of_results = 100
    if days_back < 0:
        days_back = 180

    # Get similar alerts
    similar_alerts = get_related_alerts_details(alert.alert_customer_id, alert.assets, alert.iocs,
                                                open_alerts=open_alerts, open_cases=open_cases,
                                                closed_cases=closed_cases, closed_alerts=closed_alerts,
                                                days_back=days_back, number_of_results=number_of_results)

    return response_success(data=similar_alerts)


@alerts_blueprint.route('/alerts/update/<int:alert_id>', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alerts_update_route(alert_id) -> Response:
    """
    Update an alert in the database

    args:
        caseid (str): The case id
        alert_id (int): The alert id

    returns:
        Response: The response
    """
    if not request.json:
        return response_error('No JSON data provided')

    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Alert not found')

    if not user_has_client_access(current_user.id, alert.alert_customer_id):
        return response_error('User not entitled to update alerts for the client', status=403)

    alert_schema = AlertSchema()

    do_resolution_hook = False
    do_status_hook = False

    try:
        # Load the JSON data from the request
        data = request.get_json()
        iocs_list = data.pop('alert_iocs', None)

        activity_data = []
        for key, value in data.items():
            old_value = getattr(alert, key, None)

            if type(old_value) is int:
                old_value = str(old_value)

            if type(value) is int:
                value = str(value)

            if old_value != value:
                if key == "alert_resolution_status_id":
                    do_resolution_hook = True
                if key == 'alert_status_id':
                    do_status_hook = True

                if key not in ["alert_content", "alert_note"]:
                    activity_data.append(f"\"{key}\" from \"{old_value}\" to \"{value}\"")
                else:
                    activity_data.append(f"\"{key}\"")

        # Deserialize the JSON data into an Alert object
        updated_alert = alert_schema.load(data, instance=alert, partial=True)
        if data.get('alert_owner_id') is None and updated_alert.alert_owner_id is None:
            updated_alert.alert_owner_id = current_user.id

        if data.get('alert_owner_id') == "-1" or data.get('alert_owner_id') == -1:
            updated_alert.alert_owner_id = None

        added_iocs = 0
        updated_iocs = 0
        if iocs_list is not None:
            if not isinstance(iocs_list, list):
                return response_error('Invalid alert_iocs format')
            ioc_schema = IocSchema()
            type_index, type_validation_by_id = _build_type_maps()
            iocs_list = _sanitize_iocs(iocs_list, type_validation_by_id)
            raw_event = data.get('alert_source_content', alert.alert_source_content)
            extracted_iocs = _extract_iocs_from_raw(raw_event, type_index, type_validation_by_id)
            if _parse_raw_event(raw_event) is not None:
                allowed_values = {
                    (ioc.get("ioc_value") or "").strip().lower()
                    for ioc in extracted_iocs
                    if (ioc.get("ioc_value") or "").strip()
                }
                filtered_iocs = [
                    ioc for ioc in iocs_list
                    if (ioc.get("ioc_value") or "").strip().lower() in allowed_values
                ]
                iocs_list = _merge_iocs(filtered_iocs, extracted_iocs)
            else:
                iocs_list = _merge_iocs(iocs_list, extracted_iocs)

            new_iocs = ioc_schema.load(iocs_list, many=True)

            existing_by_value = {}
            for existing_ioc in alert.iocs:
                value_key = str(existing_ioc.ioc_value or '').lower()
                if value_key not in existing_by_value:
                    existing_by_value[value_key] = []
                existing_by_value[value_key].append(existing_ioc)

            for ioc in new_iocs:
                value_key = (ioc.ioc_value or '').lower()
                if value_key in existing_by_value:
                    if ioc.ioc_type_id:
                        for existing_ioc in existing_by_value[value_key]:
                            if existing_ioc.ioc_type_id is None:
                                existing_ioc.ioc_type_id = ioc.ioc_type_id
                                updated_iocs += 1
                    continue
                alert.iocs.append(ioc)
                existing_by_value[value_key] = [ioc]
                added_iocs += 1

            if added_iocs or updated_iocs:
                update_msg = f"\"alert_iocs\" added {added_iocs}"
                if updated_iocs:
                    update_msg += f", updated {updated_iocs}"
                activity_data.append(update_msg)
                
        # Save the changes
        db.session.commit()

        updated_alert = call_modules_hook('on_postload_alert_update', data=updated_alert)

        if do_resolution_hook:
            updated_alert = call_modules_hook('on_postload_alert_resolution_update', data=updated_alert)

        if do_status_hook:
            updated_alert = call_modules_hook('on_postload_alert_status_update', data=updated_alert)

        if activity_data:
            track_activity(f"updated alert #{alert_id}: {','.join(activity_data)}", ctx_less=True)
            add_obj_history_entry(updated_alert, f"updated alert: {','.join(activity_data)}")
        else:
            track_activity(f"updated alert #{alert_id}", ctx_less=True)
            add_obj_history_entry(updated_alert, f"updated alert")

        db.session.commit()

        # Return the updated alert as JSON
        return response_success(data=alert_schema.dump(updated_alert))

    except Exception as e:
        # Handle any errors during deserialization or DB operations
        return response_error(str(e))


@alerts_blueprint.route('/alerts/batch/update', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alerts_batch_update_route() -> Response:
    """
    Update multiple alerts in the database

    args:
        caseid (int): The case id

    returns:
        Response: The response
    """
    if not request.json:
        return response_error('No JSON data provided')

    # Load the JSON data from the request
    data = request.get_json()

    # Get the list of alert IDs and updates from the request data
    alert_ids: List[int] = data.get('alert_ids', [])
    updates = data.get('updates', {})

    if not updates.get('alert_tags'):
        updates.pop('alert_tags', None)

    if not alert_ids:
        return response_error('No alert IDs provided')

    alert_schema = AlertSchema()

    # Process each alert ID
    for alert_id in alert_ids:
        alert = get_alert_by_id(alert_id)
        if not alert:
            return response_error(f'Alert with ID {alert_id} not found')

        try:

            activity_data = []
            for key, value in updates.items():
                old_value = getattr(alert, key, None)

                if old_value != value:
                    activity_data.append(f"\"{key}\"")

            # Check if the user has access to the client
            if not user_has_client_access(current_user.id, alert.alert_customer_id):
                return response_error('User not entitled to update alerts for the client', status=403)

            if getattr(alert, 'alert_owner_id') is None:
                updates['alert_owner_id'] = current_user.id

            if data.get('alert_owner_id') == "-1" or data.get('alert_owner_id') == -1:
                updates['alert_owner_id'] = None

            # Deserialize the JSON data into an Alert object
            alert_schema.load(updates, instance=alert, partial=True)

            db.session.commit()

            alert = call_modules_hook('on_postload_alert_update', data=alert)

            if activity_data:
                track_activity(f"updated alert #{alert_id}: {','.join(activity_data)}", ctx_less=True)
                add_obj_history_entry(alert, f"updated alert: {','.join(activity_data)}")

            db.session.commit()

        except Exception as e:
            # Handle any errors during deserialization or DB operations
            return response_error(str(e))

    # Return a success response
    return response_success(msg='Batch update successful')


@alerts_blueprint.route('/alerts/batch/delete', methods=['POST'])
@ac_api_requires(Permissions.alerts_delete)
def alerts_batch_delete_route() -> Response:
    """
    Delete multiple alerts from the database

    args:
        caseid (int): The case id

    returns:
        Response: The response
    """
    if not request.json:
        return response_error('No JSON data provided')

    # Load the JSON data from the request
    data = request.get_json()

    # Get the list of alert IDs and updates from the request data
    alert_ids: List[int] = data.get('alert_ids', [])

    if not alert_ids:
        return response_error('No alert IDs provided')

    # Check if the user has access to the client
    for alert_id in alert_ids:
        alert = get_alert_by_id(alert_id)
        if not alert:
            return response_error(f'Alert with ID {alert_id} not found')

        if not user_has_client_access(current_user.id, alert.alert_customer_id):
            return response_error('User not entitled to delete alerts for the client', status=403)

    success, logs = delete_alerts(alert_ids)

    if not success:
        return response_error(logs)
    
    alert = call_modules_hook('on_postload_alert_delete', data={"alert_ids": alert_ids})

    track_activity(f"deleted alerts #{','.join(str(alert_id) for alert_id in alert_ids)}", ctx_less=True)

    return response_success(msg='Batch delete successful')


@alerts_blueprint.route('/alerts/delete/<int:alert_id>', methods=['POST'])
@ac_api_requires(Permissions.alerts_delete)
def alerts_delete_route(alert_id) -> Response:
    """
    Delete an alert from the database

    args:
        caseid (str): The case id
        alert_id (int): The alert id

    returns:
        Response: The response
    """

    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Alert not found')

    try:

        # Check if the user has access to the client
        if not user_has_client_access(current_user.id, alert.alert_customer_id):
            return response_error('User not entitled to delete alerts for the client', status=403)

        # Delete the case association
        delete_similar_alert_cache(alert_id=alert_id)

        # Delete the similarity entries
        delete_related_alerts_cache([alert_id])

        # Delete the alert from the database
        db.session.delete(alert)
        db.session.commit()

        alert = call_modules_hook('on_postload_alert_delete', data=alert_id)

        track_activity(f"delete alert #{alert_id}", ctx_less=True)

        # Return the deleted alert as JSON
        return response_success(data={'alert_id': alert_id})

    except Exception as e:
        # Handle any errors during deserialization or DB operations
        return response_error(str(e))


@alerts_blueprint.route('/alerts/escalate/<int:alert_id>', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alerts_escalate_route(alert_id) -> Response:
    """
    Escalate an alert

    args:
        caseid (str): The case id
        alert_id (int): The alert id

    returns:
        Response: The response
    """

    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Alert not found')

    if request.json is None:
        return response_error('No JSON data provided')

    data = request.get_json()

    iocs_import_list: List[str] = data.get('iocs_import_list')
    assets_import_list: List[str] = data.get('assets_import_list')
    note: str = data.get('note')
    import_as_event: bool = data.get('import_as_event')
    case_tags: str = data.get('case_tags')
    case_title: str = data.get('case_title')
    case_template_id: int = data.get('case_template_id', None)

    try:
        # Check if the user has access to the client
        if not user_has_client_access(current_user.id, alert.alert_customer_id):
            return response_error('User not entitled to escalate alerts for the client', status=403)

        # Escalate the alert to a case
        alert.alert_status_id = AlertStatus.query.filter_by(status_name='Escalated').first().status_id
        db.session.commit()

        # Create a new case from the alert
        case = create_case_from_alert(alert, iocs_list=iocs_import_list, assets_list=assets_import_list, note=note,
                                      import_as_event=import_as_event, case_tags=case_tags, case_title=case_title,
                                      template_id=case_template_id)

        if not case:
            return response_error('Failed to create case from alert')

        ac_set_new_case_access(None, case.case_id, case.client_id)

        case = call_modules_hook('on_postload_case_create', data=case)

        add_obj_history_entry(case, 'created')
        track_activity("new case {case_name} created from alert".format(case_name=case.name),
                       ctx_less=True)

        add_obj_history_entry(alert, f"Alert escalated to case #{case.case_id}")

        alert = call_modules_hook('on_postload_alert_escalate', data=alert)

        # Return the updated alert as JSON
        return response_success(data=CaseSchema().dump(case))

    except Exception as e:

        app.logger.exception(e)

        # Handle any errors during deserialization or DB operations
        return response_error(str(e))


@alerts_blueprint.route('/alerts/merge/<int:alert_id>', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alerts_merge_route(alert_id) -> Response:
    """
    Merge an alert into a case

    args:
        caseid (str): The case id
        alert_id (int): The alert id

    returns:
        Response: The response
    """
    if request.json is None:
        return response_error('No JSON data provided')

    data = request.get_json()

    target_case_id = data.get('target_case_id')
    if target_case_id is None:
        return response_error('No target case id provided')

    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Alert not found')

    case = get_case(target_case_id)
    if not case:
        return response_error('Target case not found')

    iocs_import_list: List[str] = data.get('iocs_import_list')
    assets_import_list: List[str] = data.get('assets_import_list')
    note: str = data.get('note')
    import_as_event: bool = data.get('import_as_event')
    case_tags = data.get('case_tags')

    try:
        # Check if the user has access to the client
        if not user_has_client_access(current_user.id, alert.alert_customer_id):
            return response_error('User not entitled to merge alerts for the client', status=403)

        # Check if the user has access to the case
        if not check_ua_case_client(current_user.id, target_case_id):
            return response_error('User not entitled to merge alerts for the case', status=403)

        # Merge the alert into a case
        alert.alert_status_id = AlertStatus.query.filter_by(status_name='Merged').first().status_id
        db.session.commit()

        # Merge alert in the case
        merge_alert_in_case(alert, case,
                            iocs_list=iocs_import_list, assets_list=assets_import_list, note=note,
                            import_as_event=import_as_event, case_tags=case_tags)
        
        alert = call_modules_hook('on_postload_alert_merge', data=alert, caseid=target_case_id)

        track_activity(f"merge alert #{alert_id} into existing case #{target_case_id}", caseid=target_case_id)
        add_obj_history_entry(alert, f"Alert merged into existing case #{target_case_id}")

        # Return the updated alert as JSON
        return response_success(data=CaseSchema().dump(case))

    except Exception as e:
        app.app.logger.exception(e)
        # Handle any errors during deserialization or DB operations
        return response_error(str(e))


@alerts_blueprint.route('/alerts/unmerge/<int:alert_id>', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alerts_unmerge_route(alert_id) -> Response:
    """
    Unmerge an alert from a case

    args:
        caseid (str): The case id
        alert_id (int): The alert id

    returns:
        Response: The response
    """
    if request.json is None:
        return response_error('No JSON data provided')

    target_case_id = request.json.get('target_case_id')
    if target_case_id is None:
        return response_error('No target case id provided')

    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Alert not found')

    case = get_case(target_case_id)
    if not case:
        return response_error('Target case not found')

    try:
        # Check if the user has access to the client
        if not user_has_client_access(current_user.id, alert.alert_customer_id):
            return response_error('User not entitled to unmerge alerts for the client', status=403)

        # Check if the user has access to the case
        if not check_ua_case_client(current_user.id, target_case_id):
            return response_error('User not entitled to unmerge alerts for the case', status=403)

        # Unmerge alert from the case
        success, message = unmerge_alert_from_case(alert, case)

        if success is False:
            return response_error(message)

        track_activity(f"unmerge alert #{alert_id} from case #{target_case_id}", caseid=target_case_id)
        add_obj_history_entry(alert, f"Alert unmerged from case #{target_case_id}")

        alert = call_modules_hook('on_postload_alert_unmerge', data=alert)

        # Return the updated case as JSON
        return response_success(data=AlertSchema().dump(alert), msg=message)

    except Exception as e:
        # Handle any errors during deserialization or DB operations
        return response_error(str(e))


@alerts_blueprint.route('/alerts/batch/merge', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alerts_batch_merge_route() -> Response:
    """
    Merge multiple alerts into a case

    args:
        caseid (str): The case id

    returns:
        Response: The response
    """
    if request.json is None:
        return response_error('No JSON data provided')

    data = request.get_json()

    target_case_id = data.get('target_case_id')
    if target_case_id is None:
        return response_error('No target case id provided')

    alert_ids = data.get('alert_ids')
    if not alert_ids:
        return response_error('No alert ids provided')

    case = get_case(target_case_id)
    if not case:
        return response_error('Target case not found')

    iocs_import_list: List[str] = data.get('iocs_import_list')
    assets_import_list: List[str] = data.get('assets_import_list')
    note: str = data.get('note')
    import_as_event: bool = data.get('import_as_event')
    case_tags = data.get('case_tags')

    # Check if the user has access to the case
    if not check_ua_case_client(current_user.id, target_case_id):
        return response_error('User not entitled to merge alerts for the case', status=403)

    try:
        # Merge the alerts into a case
        for alert_id in alert_ids.split(','):
            alert_id = int(alert_id)

            alert = get_alert_by_id(alert_id)
            if not alert:
                continue

            # Check if the user has access to the client
            if not user_has_client_access(current_user.id, alert.alert_customer_id):
                return response_error('User not entitled to merge alerts for the client', status=403)

            alert.alert_status_id = AlertStatus.query.filter_by(status_name='Merged').first().status_id
            db.session.commit()

            # Merge alert in the case
            merge_alert_in_case(alert, case, iocs_list=iocs_import_list, assets_list=assets_import_list, note=None,
                                import_as_event=import_as_event, case_tags=case_tags)

            add_obj_history_entry(alert, f"Alert merged into existing case #{target_case_id}")

            alert = call_modules_hook('on_postload_alert_merge', data=alert)

        if note:
            case.description += f"\n\n### Escalation note\n\n{note}\n\n" if case.description else f"\n\n{note}\n\n"
            db.session.commit()

        track_activity(f"batched merge alerts {alert_ids} into existing case #{target_case_id}",
                       caseid=target_case_id)

        # Return the updated case as JSON
        return response_success(data=CaseSchema().dump(case))

    except Exception as e:
        app.app.logger.exception(e)
        # Handle any errors during deserialization or DB operations
        return response_error(str(e))


@alerts_blueprint.route('/alerts/batch/escalate', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alerts_batch_escalate_route() -> Response:
    """
    Escalate multiple alerts into a case

    args:
        caseid (str): The case id

    returns:
        Response: The response
    """
    if request.json is None:
        return response_error('No JSON data provided')

    data = request.get_json()

    alert_ids = data.get('alert_ids')
    if not alert_ids:
        return response_error('No alert ids provided')

    iocs_import_list: List[str] = data.get('iocs_import_list')
    assets_import_list: List[str] = data.get('assets_import_list')
    note: str = data.get('note')
    import_as_event: bool = data.get('import_as_event')
    case_tags = data.get('case_tags')
    case_title = data.get('case_title')
    alerts_list = []
    case_template_id: int = data.get('case_template_id', None)

    try:
        # Merge the alerts into a case
        for alert_id in alert_ids.split(','):
            alert_id = int(alert_id)

            alert = get_alert_by_id(alert_id)
            if not alert:
                continue

            # Check if the user has access to the client
            if not user_has_client_access(current_user.id, alert.alert_customer_id):
                return response_error('User not entitled to escalate alerts for the client', status=403)

            alert.alert_status_id = AlertStatus.query.filter_by(status_name='Merged').first().status_id
            db.session.commit()
            alert = call_modules_hook('on_postload_alert_escalate', data=alert)

            alerts_list.append(alert)

        # Merge alerts in the case
        case = create_case_from_alerts(alerts_list, iocs_list=iocs_import_list, assets_list=assets_import_list,
                                       note=note, import_as_event=import_as_event, case_tags=case_tags,
                                       case_title=case_title, template_id=case_template_id)

        if not case:
            return response_error('Failed to create case from alert')

        ac_set_new_case_access(None, case.case_id, case.client_id)

        case = call_modules_hook('on_postload_case_create', data=case)

        add_obj_history_entry(case, 'created')
        track_activity("new case {case_name} created from alerts".format(case_name=case.name),
                       caseid=case.case_id)

        for alert in alerts_list:
            add_obj_history_entry(alert, f"Alert escalated into new case #{case.case_id}")

        # Return the updated case as JSON
        return response_success(data=CaseSchema().dump(case))

    except Exception as e:
        app.app.logger.exception(e)
        # Handle any errors during deserialization or DB operations
        return response_error(str(e))


@alerts_blueprint.route('/alerts', methods=['GET'])
@ac_requires(Permissions.alerts_read, no_cid_required=True)
def alerts_list_view_route(caseid, url_redir) -> Union[str, Response]:
    """
    List all alerts

    args:
        caseid (str): The case id

    returns:
        Response: The response
    """
    if url_redir:
        return redirect(url_for('alerts.alerts_list_view_route', cid=caseid))

    form = FlaskForm()

    return render_template('alerts.html', caseid=caseid, form=form)


@alerts_blueprint.route('/alerts/<int:cur_id>/comments/modal', methods=['GET'])
@ac_requires(Permissions.alerts_read, no_cid_required=True)
def alert_comment_modal(cur_id, caseid, url_redir):
    """
    Get the modal for the alert comments

    args:
        cur_id (int): The alert id
        caseid (str): The case id

    returns:
        Response: The response
    """
    if url_redir:
        return redirect(url_for('alerts.alerts_list_view_route', cid=caseid, redirect=True))

    alert = get_alert_by_id(cur_id)
    if not alert:
        return response_error('Invalid alert ID')

    if not user_has_client_access(current_user.id, alert.alert_customer_id):
        return response_error('User not entitled to update alerts for the client', status=403)

    return render_template("modal_conversation.html", element_id=cur_id, element_type='alerts',
                           title=f" alert #{alert.alert_id}")


@alerts_blueprint.route('/alerts/<int:alert_id>/comments/list', methods=['GET'])
@ac_api_requires(Permissions.alerts_read)
def alert_comments_get(alert_id):
    """
    Get the comments for an alert

    args:
        alert_id (int): The alert id
        caseid (str): The case id

    returns:
        Response: The response
    """
    # Check if the user has access to the client
    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Invalid alert ID')

    if not user_has_client_access(current_user.id, alert.alert_customer_id):
        return response_error('User not entitled to read alerts for the client', status=403)

    alert_comments = get_alert_comments(alert_id)
    if alert_comments is None:
        return response_error('Invalid alert ID')

    return response_success(data=CommentSchema(many=True).dump(alert_comments))


@alerts_blueprint.route('/alerts/<int:alert_id>/comments/<int:com_id>/delete', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alert_comment_delete(alert_id, com_id):
    """
    Delete a comment for an alert

    args:
        alert_id (int): The alert id
        com_id (int): The comment id
        caseid (str): The case id

    returns:
        Response: The response
    """
    # Check if the user has access to the client
    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Invalid alert ID')

    if not user_has_client_access(current_user.id, alert.alert_customer_id):
        return response_error('User not entitled to read alerts for the client', status=403)

    success, msg = delete_alert_comment(comment_id=com_id, alert_id=alert_id)
    if not success:
        return response_error(msg)

    call_modules_hook('on_postload_alert_comment_delete', data=com_id)

    track_activity(f"comment {com_id} on alert {alert_id} deleted", ctx_less=True)

    return response_success(msg)


@alerts_blueprint.route('/alerts/<int:alert_id>/comments/<int:com_id>', methods=['GET'])
@ac_api_requires(Permissions.alerts_read)
def alert_comment_get(alert_id, com_id):
    """
    Get a comment for an alert

    args:
        cur_id (int): The alert id
        com_id (int): The comment id
        caseid (str): The case id

    returns:
        Response: The response
    """
    # Check if the user has access to the client
    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Invalid alert ID')

    if not user_has_client_access(current_user.id, alert.alert_customer_id):
        return response_error('User not entitled to read alerts for the client', status=403)

    comment = get_alert_comment(alert_id, com_id)
    if not comment:
        return response_error("Invalid comment ID")

    return response_success(data=CommentSchema().dump(comment))


@alerts_blueprint.route('/alerts/<int:alert_id>/comments/<int:com_id>/edit', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def alert_comment_edit(alert_id, com_id):
    """
    Edit a comment for an alert

    args:
        alert_id (int): The alert id
        com_id (int): The comment id
        caseid (str): The case id

    returns:
        Response: The response
    """
    alert = get_alert_by_id(alert_id)
    if not alert:
        return response_error('Invalid alert ID')

    if not user_has_client_access(current_user.id, alert.alert_customer_id):
        return response_error('User not entitled to read alerts for the client', status=403)

    return case_comment_update(com_id, 'events', None)


@alerts_blueprint.route('/alerts/<int:alert_id>/comments/add', methods=['POST'])
@ac_api_requires(Permissions.alerts_write)
def case_comment_add(alert_id):
    """
    Add a comment to an alert

    args:
        alert_id (int): The alert id
        caseid (str): The case id

    returns:
        Response: The response
    """

    try:
        alert = get_alert_by_id(alert_id=alert_id)
        if not alert:
            return response_error('Invalid alert ID')

        if not user_has_client_access(current_user.id, alert.alert_customer_id):
            return response_error('User not entitled to read alerts for the client', status=403)

        comment_schema = CommentSchema()

        comment = comment_schema.load(request.get_json())
        comment.comment_alert_id = alert_id
        comment.comment_user_id = current_user.id
        comment.comment_date = datetime.now()
        comment.comment_update_date = datetime.now()
        db.session.add(comment)
        db.session.commit()

        add_obj_history_entry(alert, 'commented')

        db.session.commit()

        hook_data = {
            "comment": comment_schema.dump(comment),
            "alert": AlertSchema().dump(alert)
        }
        call_modules_hook('on_postload_alert_commented', data=hook_data)

        track_activity(f"alert \"{alert.alert_id}\" commented", ctx_less=True)
        return response_success("Alert commented", data=comment_schema.dump(comment))

    except marshmallow.exceptions.ValidationError as e:
        return response_error(msg="Data error", data=e.normalized_messages())
