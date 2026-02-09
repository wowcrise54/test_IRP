let sortOrder ;
let editor = null;

function objectToQueryString(obj) {
  return Object.keys(obj)
    .filter(key => obj[key] !== undefined && obj[key] !== null && obj[key] !== '')
    .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(obj[key]))
    .join('&');
}

async function fetchAlert(alertId) {
    const response = get_raw_request_api(`/alerts/${alertId}?cid=${get_caseid()}`);
    return await response;
}

async function fetchMultipleAlerts(alertIds) {
    const response = get_raw_request_api(`/alerts/filter?cid=${get_caseid()}&alert_ids=${alertIds.join(',')}`);
    return await response;
}

let iocTypesCache = null;

const IOC_EXTRACT_PATTERNS = [
    { key: 'url', regex: /\b(?:https?|hxxps?):\/\/[^\s"'<>()[\]{}]+/gi },
    { key: 'email', regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi },
    { key: 'ipv4', regex: /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g },
    { key: 'ipv6', regex: /\b(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|:(?::[A-Fa-f0-9]{1,4}){1,7})\b/g },
    { key: 'md5', regex: /\b[a-f0-9]{32}\b/gi },
    { key: 'sha1', regex: /\b[a-f0-9]{40}\b/gi },
    { key: 'sha256', regex: /\b[a-f0-9]{64}\b/gi },
    { key: 'sha512', regex: /\b[a-f0-9]{128}\b/gi },
    { key: 'domain', regex: /\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\b/gi }
];

async function fetchIocTypes() {
    if (iocTypesCache !== null) {
        return iocTypesCache;
    }
    const response = await get_request_api('/manage/ioc-types/list');
    if (!notify_auto_api(response, true, true)) {
        return null;
    }
    iocTypesCache = response.data || [];
    return iocTypesCache;
}

function buildIocTypeMap(iocTypes) {
    const typeMap = {};
    (iocTypes || []).forEach((type) => {
        if (type.type_name) {
            typeMap[type.type_name.toLowerCase()] = type.type_id;
        }
    });
    return typeMap;
}

function normalizeAlertSourceContent(content) {
    if (content === undefined || content === null) {
        return '';
    }
    if (typeof content === 'string') {
        return content;
    }
    try {
        return JSON.stringify(content);
    } catch (err) {
        return String(content);
    }
}

function defangText(text) {
    if (!text) {
        return text;
    }
    let normalized = String(text);
    normalized = normalized.replace(/[\[\(\{]\s*\.\s*[\]\)\}]/g, '.');
    normalized = normalized.replace(/[\[\(\{]\s*:\s*[\]\)\}]/g, ':');
    normalized = normalized.replace(/[\[\(\{]\s*\/\s*[\]\)\}]/g, '/');
    normalized = normalized.replace(/[\[\(\{]\s*@\s*[\]\)\}]/g, '@');
    normalized = normalized.replace(/hxxps?:\/\//gi, (match) => {
        return match.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://';
    });
    normalized = normalized.replace(/\bhxxps\b/gi, 'https');
    normalized = normalized.replace(/\bhxxp\b/gi, 'http');
    return normalized;
}

function stripEdgePunctuation(value) {
    return value
        .replace(/^[\s"'(<\[{]+/, '')
        .replace(/[\s"'`)\]}>.,;:!?]+$/, '');
}

function normalizeIocValue(value, typeKey) {
    if (!value) {
        return null;
    }
    let normalized = value.trim();
    if (!normalized) {
        return null;
    }

    if (typeKey === 'url') {
        normalized = stripEdgePunctuation(normalized);
    } else {
        normalized = stripEdgePunctuation(normalized);
    }

    if (['md5', 'sha1', 'sha256', 'sha512', 'domain', 'email', 'ipv6'].includes(typeKey)) {
        normalized = normalized.toLowerCase();
    }

    return normalized || null;
}

function resolveIocTypeId(typeMap, candidates) {
    for (const name of candidates) {
        const typeId = typeMap[name];
        if (typeId) {
            return typeId;
        }
    }
    return null;
}

function extractIocsFromContent(content, iocTypeMap) {
    let text = normalizeAlertSourceContent(content);
    if (!text) {
        return [];
    }
    text = defangText(text);

    const results = [];
    const seen = new Set();

    const typeIdForKey = (typeKey) => {
        switch (typeKey) {
            case 'url':
                return resolveIocTypeId(iocTypeMap, ['url', 'uri', 'link']);
            case 'domain':
                return resolveIocTypeId(iocTypeMap, ['domain']);
            case 'email':
                return resolveIocTypeId(iocTypeMap, ['email', 'email-src', 'email-dst']);
            case 'ipv4':
            case 'ipv6':
                return resolveIocTypeId(iocTypeMap, ['ip-any', 'ip-src', 'ip-dst']);
            case 'md5':
                return resolveIocTypeId(iocTypeMap, ['md5']);
            case 'sha1':
                return resolveIocTypeId(iocTypeMap, ['sha1']);
            case 'sha256':
                return resolveIocTypeId(iocTypeMap, ['sha256']);
            case 'sha512':
                return resolveIocTypeId(iocTypeMap, ['sha512']);
            default:
                return null;
        }
    };

    IOC_EXTRACT_PATTERNS.forEach((pattern) => {
        if (!pattern.regex) {
            return;
        }
        pattern.regex.lastIndex = 0;
        const matches = text.match(pattern.regex) || [];
        matches.forEach((match) => {
            const normalized = normalizeIocValue(match, pattern.key);
            if (!normalized) {
                return;
            }
            const typeId = typeIdForKey(pattern.key);
            const dedupeKey = `${pattern.key}:${normalized.toLowerCase()}:${typeId || 'none'}`;
            if (seen.has(dedupeKey)) {
                return;
            }
            seen.add(dedupeKey);
            const entry = { ioc_value: normalized };
            if (typeId) {
                entry.ioc_type_id = typeId;
            }
            results.push(entry);
        });
    });

    return results;
}

async function enrichAlertsIocs(alertIds) {
    if (!alertIds || alertIds.length === 0) {
        notify_error(t('Please select at least one alert to perform this action on.'));
        return;
    }

    window.swal({
        title: t('Extracting IOCs, please wait'),
        text: t("This window will close automatically when it's done"),
        icon: "/static/assets/img/loader.gif",
        button: false,
        allowOutsideClick: false
    });

    let updatedAlerts = 0;
    let failedAlerts = 0;
    let emptyAlerts = 0;
    let totalIocs = 0;

    try {
        const iocTypes = await fetchIocTypes();
        if (!iocTypes) {
            notify_error(t('Unable to load IOC types.'));
            return;
        }
        const iocTypeMap = buildIocTypeMap(iocTypes);

        for (const alertId of alertIds) {
            const alertReq = await fetchAlert(alertId);
            if (!notify_auto_api(alertReq, true, true)) {
                failedAlerts += 1;
                continue;
            }
            const alertData = alertReq.data;
            const iocs = extractIocsFromContent(alertData.alert_source_content, iocTypeMap);
            if (iocs.length === 0) {
                emptyAlerts += 1;
                continue;
            }

            const updateReq = await post_request_api(`/alerts/update/${alertId}`, JSON.stringify({
                alert_iocs: iocs,
                csrf_token: $('#csrf_token').val()
            }));
            if (!notify_auto_api(updateReq, true, true)) {
                failedAlerts += 1;
                continue;
            }

            updatedAlerts += 1;
            totalIocs += iocs.length;
        }
    } finally {
        window.swal.close();
    }

    if (updatedAlerts > 0) {
        notify_success(t('Found {ioc_count} IOC(s) in {alert_count} alert(s).', {
            ioc_count: totalIocs,
            alert_count: updatedAlerts
        }));
        if (alertIds.length === 1) {
            refreshAlert(alertIds[0]);
        } else {
            refreshAlerts();
        }
    } else if (emptyAlerts > 0 && failedAlerts === 0) {
        notify_error(t('No IOCs found in selected alerts.'));
    }

    if (failedAlerts > 0) {
        notify_error(t('Failed to enrich {count} alert(s).', { count: failedAlerts }));
    }
}

const selectsConfig = {
    alert_status_id: {
        url: '/manage/alert-status/list',
        id: 'status_id',
        name: 'status_name',
    },
    alert_severity_id: {
        url: '/manage/severities/list',
        id: 'severity_id',
        name: 'severity_name'
    },
    alert_classification_id: {
        url: '/manage/case-classifications/list',
        id: 'id',
        name: 'name_expanded',
    },
    alert_customer_id: {
        url: '/manage/customers/list',
        id: 'customer_id',
        name: 'customer_name'
    },
    alert_owner_id: {
        url: '/manage/users/restricted/list',
        id: 'user_id',
        name: 'user_name'
    },
    alert_resolution_id: {
        url: '/manage/alert-resolutions/list',
        id: 'resolution_status_id',
        name: 'resolution_status_name'
    }
};

let alertStatusList = {};
let alertResolutionList = {};

function getAlertStatusList() {
    get_request_api('/manage/alert-status/list')
        .then((data) => {
            if (!notify_auto_api(data, true)) {
                return;
            }
            alertStatusList = data.data;
        });
}

function getAlertResolutionList() {
    get_request_api('/manage/alert-resolutions/list')
        .then((data) => {
            if (!notify_auto_api(data, true)) {
                return;
            }
            alertResolutionList = data.data;
        });
}

function getAlertStatusId(statusName) {
    const status = alertStatusList.find((status) => status.status_name === statusName);
    return status ? status.status_id : undefined;
}

function getAlertResolutionId(resolutionName) {
    if (alertResolutionList.length === undefined) {
        getAlertResolutionList();
    }
    const resolution = alertResolutionList.find((resolution) => resolution.resolution_status_name.toLowerCase().replaceAll(' ', '_') === resolutionName);
    return resolution ? resolution.resolution_status_id : undefined;
}

function appendLabels(list, items, itemType) {
    items.forEach((item) => {
        const label = $('<label></label>').addClass('d-block');
        const input = $('<input>').attr({
            type: 'checkbox',
            name: itemType,
            value: filterXSS(item[itemType + '_name'] || item[itemType + '_value']),
            id: item[itemType + '_uuid'],
            checked: true,
        });
        label.append(input);
        label.append(`${filterXSS(item[itemType + '_name'] || item[itemType + '_value'])}`);
        list.append(label);
    });
}

function toggleSelectDeselect(toggleButton, listSelector) {
    let allChecked = true;
    $(listSelector).each(function () {
        if (!$(this).prop("checked")) {
            allChecked = false;
        }
        $(this).prop("checked", !$(this).prop("checked"));
    });

    if (allChecked) {
        toggleButton.text(t("Select all"));
    } else {
        toggleButton.text(t("Deselect all"));
    }
}

function unlinkAlertFromCase(alert_id, case_id) {

    do_deletion_prompt(t('Unlink alert #{alert_id} from the case #{case_id}?', {
        alert_id: alert_id,
        case_id: case_id
    }), true)
        .then( () => {
            unlinkAlertFromCaseRequest(alert_id, case_id)
                .then((data) => {
                    if (!notify_auto_api(data)) {
                        return;
                    }
                    refreshAlert(alert_id);
                });
    });

}

async function unlinkAlertFromCaseRequest(alert_id, case_id) {
    return await post_request_api(`/alerts/unmerge/${alert_id}`, JSON.stringify({
        target_case_id: case_id,
        csrf_token: $('#csrf_token').val()
    }));
}

function mergeMultipleAlertsModal() {
    const selectedAlerts = getBatchAlerts();
    const escalateButton = $("#escalateOrMergeButton");
    if (selectedAlerts.length === 0) {
        notify_error(t('Please select at least one alert to perform this action on.'));
        return;
    }
    fetchMultipleAlerts(selectedAlerts)
        .then((alertDataReq) => {
            if (notify_auto_api(alertDataReq, true)) {
                const ioCsList = $("#ioCsList");
                    const assetsList = $("#assetsList");

                    // Configure the modal for both escalation and merging
                    $('#escalateModalLabel').text(t('Merge multiple alerts in a new case'));
                    $('#escalateModalExplanation').text(t('These alerts will be merged into a new case. Set the case title and select the IOCs and Assets to escalate into the case.'));
                    $('#modalAlertTitleContainer').hide();

                    $('#modalEscalateCaseTitle').val(t('[ALERT] Escalation of {count} alerts', { count: selectedAlerts.length }));
                    $('#modalEscalateCaseTitleContainer').show();

                    escalateButton.attr("data-merge", false);
                    $('#mergeAlertCaseSelectSection').hide();

                    const case_tags = $('#case_tags');

                    case_tags.val('')
                    case_tags.amsifySuggestags({
                        printValues: false,
                        suggestions: []
                    });

                    // Load case options for merging
                    var options = {
                        ajax: {
                            url: '/context/search-cases' + case_param(),
                            type: 'GET',
                            dataType: 'json'
                        },
                        minLength: 0,
                        clearOnEmpty: false,
                        emptyRequest: true,
                        locale: {
                            emptyTitle: t('Select and begin typing'),
                            statusInitialized: '',
                        },
                        preprocessData: function (data) {
                            return context_data_parser(data);
                        },
                        preserveSelected: false
                    };
                    get_request_api('/context/search-cases')
                        .done((data) => {
                            if (notify_auto_api(data, true)) {
                                mergeAlertCasesSelectOption(data);
                                $('#mergeAlertCaseSelect').ajaxSelectPicker(options);

                                get_request_api('/manage/case-templates/list')
                                .done((dataTemplate) => {
                                    if (notify_auto_api(dataTemplate, true)) {
                                        dataTemplate = dataTemplate.data;
                                        const templateSelect = $('#mergeAlertCaseTemplateSelect');
                                        templateSelect.html('');
                                        templateSelect.append(`<option value="">${t('Select a template')}</option>`);
                                        for (let i = 0; i < dataTemplate.length; i++) {
                                            templateSelect.append(`<option value="${dataTemplate[i].id}">${filterXSS(dataTemplate[i].display_name)}</option>`);
                                        }
                                        templateSelect.selectpicker('refresh');

                                        // Clear the lists
                                        ioCsList.html("");
                                        assetsList.html("");

                                        let alertsData = alertDataReq.data;

                                        for (let i = 0; i < alertsData.length; i++) {
                                            let alertData = alertsData[i];
                                            if (alertData.iocs.length !== 0) {
                                                appendLabels(ioCsList, alertData.iocs, 'ioc');
                                            }
                                            if (alertData.assets.length !== 0) {
                                                appendLabels(assetsList, alertData.assets, 'asset');
                                            }
                                        }

                                        escalateButton.attr("data-merge", false);
                                        escalateButton.attr("data-multi-merge", true);
                                        $("#escalateOrMergeButton").attr('onclick',
                                            `mergeAlertClicked("${selectedAlerts.join(',')}");`);

                                        $('#escalateModal').modal('show');

                                        $("input[type='radio'][name='mergeOption']:checked").trigger("change");

                                        $("input[type='radio'][name='mergeOption']").off('change').on("change", function () {
                                            if ($(this).val() === "existing_case") {
                                                $('#escalateModalLabel').text(t('Merge {count} alerts in an existing case', { count: selectedAlerts.length }));
                                                $('#escalateModalExplanation').text(t('These alerts will be merged into the selected case. Select the IOCs and Assets to merge into the case.'));
                                                $('#mergeAlertCaseSelectSection').show();
                                                $('#mergeAlertCaseTemplateSection').hide();
                                                $('#modalEscalateCaseTitleContainer').hide();
                                                $('#mergeAlertCaseSelect').selectpicker('refresh');
                                                $('#mergeAlertCaseSelect').selectpicker('val', get_caseid());
                                                escalateButton.data("merge", true);
                                            } else {
                                                $('#escalateModalLabel').text(t('Merge {count} alerts in a new case', { count: selectedAlerts.length }));
                                                $('#escalateModalExplanation').text(t('This alert will be merged into a new case. Set the case title and select the IOCs and Assets to merge into the case.'));
                                                $('#mergeAlertCaseSelectSection').hide();
                                                $('#mergeAlertCaseTemplateSection').show();
                                                $('#modalEscalateCaseTitleContainer').show();
                                                escalateButton.data("merge", false);
                                            }
                                        });
                                    }
                                });
                            }
                        });
            }
        });


}

function showEscalationModal() {
    $("#escalateModal").modal("show");
}

function mergeAlertModal(alert_id) {

    const escalateButton = $("#escalateOrMergeButton");
    escalateButton.attr("data-alert-id", alert_id);

    let alertDataReq = null;
    const ioCsList = $("#ioCsList");
    const assetsList = $("#assetsList");

    fetchAlert(alert_id)
        .then((data) => {
            alertDataReq = data;
            notify_auto_api(data, true);
            let alert_title = filterXSS(alertDataReq.data.alert_title);

            $("#modalAlertId").val(alert_id);
            $("#modalAlertTitle").val(alert_title);

            // Configure the modal for both escalation and merging
            $('#escalateModalLabel').html(t('Merge alert #{id} in a new case', { id: alert_id }));
            $('#escalateModalLabel')[0].offsetHeight;

            $('#escalateModalExplanation').text(t('This alert will be escalated into a new case. Set a title and select the IOCs and Assets to escalate into the case.'));

            $('#modalEscalateCaseTitle').val(`[ALERT] ${alert_title}`);
            $('#modalEscalateCaseTitleContainer').show();

            escalateButton.attr("data-merge", false);
            $('#mergeAlertCaseSelectSection').hide();

            const case_tags = $('#case_tags');

            case_tags.val(alertDataReq.data.alert_tags)
            case_tags.amsifySuggestags({
                printValues: false,
                suggestions: []
            });

            // Load case options for merging
            var options = {
                ajax: {
                    url: '/context/search-cases' + case_param(),
                    type: 'GET',
                    dataType: 'json'
                },
                minLength: 0,
                clearOnEmpty: false,
                emptyRequest: true,
                locale: {
                    emptyTitle: t('Select and begin typing'),
                    statusInitialized: '',
                },
                preprocessData: function (data) {
                    return context_data_parser(data, false);
                },
                preserveSelected: false
            };

            get_request_api('/context/search-cases')
            .done((data) => {
                if (notify_auto_api(data, true)) {
                    mergeAlertCasesSelectOption(data);
                    $('#mergeAlertCaseSelect').ajaxSelectPicker(options);

                    get_request_api('/manage/case-templates/list')
                    .done((data) => {
                        if (notify_auto_api(data, true)) {
                            data = data.data;
                            const templateSelect = $('#mergeAlertCaseTemplateSelect');
                            templateSelect.html('');
                            templateSelect.append(`<option value="">${t('Select a template')}</option>`);
                            for (let i = 0; i < data.length; i++) {
                                templateSelect.append(`<option value="${data[i].id}">${filterXSS(data[i].display_name)}</option>`);
                            }
                            templateSelect.selectpicker('refresh');

                            // Clear the lists
                            ioCsList.html("");
                            assetsList.html("");

                            if (!notify_auto_api(alertDataReq, true)) {
                                return;
                            }

                            let alertData = alertDataReq.data;

                            if (alertData.iocs.length !== 0) {
                                appendLabels(ioCsList, alertData.iocs, 'ioc');
                                $("#toggle-iocs").off("click").on("click", function () {
                                    toggleSelectDeselect($(this), "#ioCsList input[type='checkbox']");
                                });
                                $("#ioc-container").show();
                            } else {
                                $("#ioc-container").show();
                            }

                            if (alertData.assets.length !== 0) {
                                appendLabels(assetsList, alertData.assets, 'asset');
                                $("#toggle-assets").off("click").on("click", function () {
                                    toggleSelectDeselect($(this), "#assetsList input[type='checkbox']");
                                });
                                $("#asset-container").show();
                            } else {
                                $("#asset-container").hide();
                            }


                            $("input[type='radio'][name='mergeOption']:checked").trigger("change");

                            $("input[type='radio'][name='mergeOption']").off("change").on("change", function () {
                                if ($(this).val() === "existing_case") {
                                    $('#escalateModalLabel').text(t('Merge alert #{id} in an existing case', { id: alert_id }));
                                    $('#escalateModalExplanation').text(t('This alert will be merged into the selected case. Select the IOCs and Assets to merge into the case.'));
                                    $('#mergeAlertCaseSelectSection').show();
                                    $('#mergeAlertCaseTemplateSection').hide();
                                    $('#modalEscalateCaseTitleContainer').hide();
                                    $('#mergeAlertCaseSelect').selectpicker('refresh');
                                    $('#mergeAlertCaseSelect').selectpicker('val', get_caseid());
                                    escalateButton.data("merge", true);
                                } else {
                                    $('#escalateModalLabel').text(t('Merge alert #{id} in a new case', { id: alert_id }));
                                    $('#escalateModalExplanation').text(t('This alert will be merged into a new case. Set the case title and select the IOCs and Assets to merge into the case.'));
                                    $('#mergeAlertCaseSelectSection').hide();
                                    $('#mergeAlertCaseTemplateSection').show();
                                    $('#modalEscalateCaseTitleContainer').show();
                                    escalateButton.data("merge", false);
                                }
                            });

                            $("#escalateOrMergeButton").attr('onclick',
                                `mergeAlertClicked(${alert_id});`);

                            $("#escalateModal").modal("show");
                        }
                    });
                }
            });


        });

}


function mergeAlertClicked(alertId) {

  const merge = $("#escalateOrMergeButton").data("merge");
  const multiMerge = $("#escalateOrMergeButton").data("multi-merge");

  escalateOrMergeAlert(alertId, merge, multiMerge);

}


function mergeAlertCasesSelectOption(data) {
    if(notify_auto_api(data, true)) {
        $('#mergeAlertCaseSelect').empty();

        $('#mergeAlertCaseSelect').append(`<optgroup label="${t('Open')}" id="switchMergeAlertCasesOpen"></optgroup>`);
        $('#mergeAlertCaseSelect').append(`<optgroup label="${t('Closed')}" id="switchMergeAlertCasesClose"></optgroup>`);
        let ocs = data.data;
        let ret_data = [];
        for (index in ocs) {
            let case_name = sanitizeHTML(ocs[index].name);
            let cs_name = sanitizeHTML(ocs[index].customer_name);
            ret_data.push({
                        'value': ocs[index].case_id,
                        'text': `${case_name} (${cs_name}) ${ocs[index].access}`
                    });
            if (ocs[index].close_date != null) {
                $('#switchMergeAlertCasesClosed').append(`<option value="${ocs[index].case_id}">${case_name} (${cs_name}) ${ocs[index].access}</option>`);
            } else {
                $('#switchMergeAlertCasesOpen').append(`<option value="${ocs[index].case_id}">${case_name} (${cs_name}) ${ocs[index].access}</option>`)
            }
        }

        return ret_data;
    }
}

function fetchSmartRelations(alert_id) {
    $(`input[name="open_alerts_${alert_id}"]`).prop('checked', true);
    $(`input[name="closed_alerts_${alert_id}"]`).prop('checked', true);
    $(`input[name="open_cases_${alert_id}"]`).prop('checked', true);
    $(`input[name="closed_cases_${alert_id}"]`).prop('checked', true);

    fetchSimilarAlerts(alert_id, false, true, true,
        true, true);
}

function buildAlertLink(alert_id){
    const current_path = location.protocol + '//' + location.host
    return current_path + '/alerts' + case_param() + '&alert_ids=' + alert_id;
}

function copyAlertLink(alert_id) {
    const link = buildAlertLink(alert_id);
    navigator.clipboard.writeText(link).then(function() {
        notify_success(t('Link copied'));
    }, function(err) {
        notify_error(t("Can't copy link. I printed it in console."));
        console.error('Shared link', err);
    });
}

function copyMDAlertLink(alert_id){
    const link = `[<i class="fa-solid fa-bell"></i> #${alert_id}](${buildAlertLink(alert_id)})`;
    navigator.clipboard.writeText(link).then(function() {
        notify_success(t('MD link copied'));
    }, function(err) {
        notify_error(t("Can't copy link. I printed it in console."));
        console.error('Shared link', err);
    });
}

function getAlertOffset(element) {
  const rect = element.getBoundingClientRect();
  return {
    left: rect.left,
    top: rect.top + window.scrollY,
  };
}

function createNetwork(alert_id, relatedAlerts, nb_nodes, containerId, containerConfigureId) {
  const { nodes, edges } = relatedAlerts;

  if (nodes.length === 0 || nodes.length === undefined) {
      $(`#similarAlertsNotify-${alert_id}`).text(t('No relationships found for this alert'));
     return;
  }

  const data = {
    nodes: new vis.DataSet(nodes),
    edges: new vis.DataSet(edges),
  };

const options = {
    edges: {
        smooth: {
            enabled: true,
            type: 'continuous',
            roundness: 0.5
        }
    },
    layout: {
        randomSeed: 2,
        improvedLayout: true
    },
    interaction: {
        hideEdgesOnDrag: false,
        tooltipDelay: 100,
        zoomView: false,
        navigationButtons: true,
        keyboard: {
            enabled: true,
            bindToWindow: true
        }
    },
    height: (window.innerHeight - 400) + "px",
    clickToUse: true,
    physics: {
        forceAtlas2Based: {
            gravitationalConstant: -167,
            centralGravity: 0.02,
            springLength: 0,
            springConstant: 0.01,
            damping: 0.1
        },
        minVelocity: 0.41,
        solver: "forceAtlas2Based",
        timestep: 0.45
    }
};

const container = document.getElementById(containerId);
const network = new vis.Network(container, data, options);


    // Create a MutationObserver to listen for DOM changes in the container
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          network.redraw(); // Force a redraw when the DOM is updated
          break;
        }
      }
    });

    // Start observing the container for DOM changes
    observer.observe(container, {
      childList: true,
      subtree: true,
    });

    network.on("stabilizationIterationsDone", function () {
        network.setOptions( { physics: false } );
    });

    let selectedNodeId = null;
    let node_type = null;
    let node_id = null;


    network.on('oncontext', (event) => {
      event.event.preventDefault();

      const nodeId = network.getNodeAt(event.pointer.DOM);

      if (nodeId) {

          selectedNodeId = nodeId;
          node_type = selectedNodeId.split('_')[0];
          node_id = selectedNodeId.split('_')[1];

          if (node_type === 'alert' || node_type === 'case' || node_type === 'asset' || node_type === 'ioc') {
              // Get the offset of the container element.
              const containerOffset = getAlertOffset(container);

              const x = event.pointer.DOM.x + 110;
              const y = containerOffset.top + event.pointer.DOM.y;

              const contextMenu = $('#context-menu-relationships');
              contextMenu.css({
                  position: 'absolute',
                  left: `${x}px`,
                  top: `${y}px`
              })

              $('#view-alert').data('node-id', node_id);
              $('#view-alert').data('node-type', node_type);
              if (node_type === 'alert' || node_type === 'case') {
                  $('#view-alert-text').text(t('View {type} #{id}', {
                      type: node_type,
                      id: node_id
                  }));
              } else {
                    $('#view-alert-text').text(t('Pivot on {type} {id}', {
                        type: node_type,
                        id: node_id
                    }));
              }
              contextMenu.show();
          }
      }
    });

    document.addEventListener('click', () => {
      const contextMenu = $('#context-menu-relationships');
      contextMenu.hide();
    });

      if (nodes.length >= nb_nodes) {
            $(`#similarAlertsNotify-${alert_id}`).text(t('Relationships node exceeded the nodes limit. Expect truncated results.'))
      } else {
            $(`#similarAlertsNotify-${alert_id}`).text(``);
      }

}

function viewAlertGraph() {
    const node_id = $("#view-alert").data('node-id');
    const node_type = $("#view-alert").data('node-type');

    if (node_type === 'alert') {
        window.open(`/alerts?alert_ids=${node_id}&cid=${get_caseid()}`);
    } else if (node_type === 'case') {
        window.open(`/case?cid=${node_id}`);
    } else if (node_type === 'asset') {
        window.open(`/alerts?alert_assets=${node_id}&cid=${get_caseid()}`);
    } else if (node_type === 'ioc') {
        window.open(`/alerts?alert_iocs=${node_id}&cid=${get_caseid()}`);
    }
}


function fetchSimilarAlerts(alert_id,
  refresh = false,
  fetch_open_alerts = true,
  fetch_closed_alerts = false,
  fetch_open_cases = false,
  fetch_closed_cases = false
    ) {
      const similarAlertsElement = $(`#similarAlerts-${alert_id}`);
      if (!similarAlertsElement.html() || refresh) {
        // Build the query string with the new parameters
        const nb_nodes = $(`#nbResultsGraphFilter-${alert_id}`).val();
        const queryString = new URLSearchParams({
          'open-alerts': fetch_open_alerts,
          'closed-alerts': fetch_closed_alerts,
          'open-cases': fetch_open_cases,
          'closed-cases': fetch_closed_cases,
          'days-back': $(`#daysBackGraphFilter-${alert_id}`).val(),
          'number-of-nodes': nb_nodes
        }).toString();

        $(`#similarAlertsNotify-${alert_id}`).text(t('Fetching relationships...'));
        get_raw_request_api(`/alerts/similarities/${alert_id}?${queryString}&cid=${get_caseid()}`)
          .done((data) => {
            createNetwork(alert_id, data.data, nb_nodes, `similarAlerts-${alert_id}`, `graphConfigure-${alert_id}`);
          });
      }
}



function escalateOrMergeAlert(alert_id, merge = false, batch = false) {

    const selectedIOCs = $('#ioCsList input[type="checkbox"]:checked').map((_, checkbox) => {
        return $(checkbox).attr('id');
    }).get();

    const selectedAssets = $('#assetsList input[type="checkbox"]:checked').map((_, checkbox) => {
        return $(checkbox).attr('id');
    }).get();

    const note = $('#note').val();
    const importAsEvent = $('#importAsEvent').is(':checked');

    let case_template_id = null;

    if (!merge) {
        case_template_id = $('#mergeAlertCaseTemplateSelect').val();
    }

    const requestBody = {
        iocs_import_list: selectedIOCs,
        assets_import_list: selectedAssets,
        note: note,
        import_as_event: importAsEvent,
        case_tags: $('#case_tags').val(),
        case_template_id: case_template_id,
        csrf_token: $("#csrf_token").val()
    };

    let url =  batch ? `/alerts/batch/`: `/alerts/`;

    if (merge) {
        requestBody.target_case_id = $('#mergeAlertCaseSelect').val();
        url += batch ? 'merge' : `merge/${alert_id}`;
    } else {
        requestBody.case_title = $('#modalEscalateCaseTitle').val();
        url += batch ? 'escalate' : `escalate/${alert_id}`;
    }

    if (batch) {
        requestBody.alert_ids = alert_id;
    }

    post_request_api(url, JSON.stringify(requestBody))
        .then((data) => {
            if (data.status == 'success') {
                $("#escalateModal").modal("hide");
                notify_auto_api(data);
                if (batch) {
                    refreshAlerts();
                } else {
                    refreshAlert(alert_id);
                }
            } else {
                notify_auto_api(data);
            }
        });
}

async function fetchAlerts(page, per_page, filters_string = {}, sort_order= 'desc') {

    const response = get_raw_request_api(`/alerts/filter?cid=${get_caseid()}&page=${page}&per_page=${per_page}
  &sort=${sort_order}&${filters_string}`);

  return await response;

}

function alert_severity_to_color(severity) {
  switch (severity) {
    case 'Critical':
      return 'critical';
    case 'High':
      return 'danger';
    case 'Medium':
      return 'warning';
    case 'Low':
      return 'low';
    case 'Informational':
      return 'info';
    default:
      return 'muted';
  }
}

function alertStatusToColor(status) {
    switch (status) {
        case 'Closed':
            return 'alert-card-done';
        case 'Dismissed':
            return 'alert-card-done';
        case 'Merged':
            return 'alert-card-done';
        case 'Escalated':
            return 'alert-card-done';
        case 'New':
            return 'alert-card-new';
        default:
            return '';
    }
}

function generateDefinitionList(obj) {
  let html = "";
  for (const key in obj) {
    const value = obj[key];
    html += `<dt>${key}:</dt>`;
    if (typeof value === "object" && value !== null) {
      html += `<dd><dl>${generateDefinitionList(value)}</dl></dd>`;
    } else {
      html += `<dd>${value}</dd>`;
    }
  }
  return html;
}

function addTagFilter(this_object) {
    let tag_name = $(this_object).data('tag');
    let filters = getFiltersFromUrl();

    if (filters['alert_tags']) {
        for (let tag of filters['alert_tags'].split(',')) {
            if (tag === tag_name) {
                return;
            }
        }
        filters['alert_tags'] += `,${tag_name}`;
    } else {
        filters['alert_tags'] = tag_name;
    }

    const queryParams = new URLSearchParams(window.location.search);
    let page_number = parseInt(queryParams.get('page'));
    let per_page = parseInt(queryParams.get('per_page'));

    updateAlerts(page_number, per_page, filters)
        .then(() => {
            notify_success('Refreshed');
            $('#newAlertsBadge').text(0).hide();
        });
}

function getFiltersFromUrl() {
    const formData = new FormData($('#alertFilterForm')[0]);
    const filters = Object.fromEntries(formData.entries());

    filters.custom_conditions = editor.getValue();

    return filters;
}

function alertResolutionToARC(resolution, alert_id) {
    if (resolution === null) {
        return '';
    }
    switch (resolution.resolution_status_name) {
        case 'True Positive With Impact':
            return `<span class="badge alert-bade-status badge-pill badge-danger mr-2" id="alertResolution-${alert_id}" data-value="true_positive_with_impact">${t('True positive with impact')}</span>`
        case 'True Positive Without Impact':
            return `<span class="badge alert-bade-status badge-pill badge-warning mr-2" id="alertResolution-${alert_id}" data-value="true_positive_without_impact">${t('True positive without impact')}</span>`
        case 'False Positive':
            return `<span class="badge alert-bade-status badge-pill badge-success mr-2" id="alertResolution-${alert_id}" data-value="false_positive">${t('False positive')}</span>`
        case 'Legitimate':
            return `<span class="badge alert-bade-status badge-pill badge-info mr-2" id="alertResolution-${alert_id}" data-value="legitimate">${t('Legitimate')}</span>`
        case 'Unknown':
            return `<span class="badge alert-bade-status badge-pill badge-light mr-2" id="alertResolution-${alert_id}" data-value="unknown">${t('Unknown resolution')}</span>`
    }
}

const ALERT_CONTEXT_KEY_LABELS = {
    'rule id': 'Rule ID',
    'rule level': 'Rule Level',
    'rule description': 'Rule Description',
    'agent id': 'Agent ID',
    'agent name': 'Agent Name',
    'mitre ids': 'MITRE IDs',
    'mitre tactics': 'MITRE Tactics',
    'mitre techniques': 'MITRE Techniques',
    'full log': 'Full Log',
    'location': 'Location'
};

function localizeAlertContextKey(key) {
    if (typeof key !== 'string') {
        return key;
    }

    const normalizedKey = key.trim().toLowerCase().replace(/[._]+/g, ' ').replace(/\s+/g, ' ');
    const translationKey = ALERT_CONTEXT_KEY_LABELS[normalizedKey] || key;

    return t(translationKey);
}

function renderNestedObject(obj) {
    let output = '';
    Object.entries(obj).forEach(([key, value]) => {
        const localizedKey = localizeAlertContextKey(key);
        if (typeof value === 'object' && value !== null) {
            output += `<dt class="col-sm-3">${filterXSS(localizedKey)}:</dt><dd class="col-sm-9"><br /><dl class="row">${renderNestedObject(value)}</dl></dd>`;
        } else {
            output += `<dt class="col-sm-3">${filterXSS(localizedKey)}:</dt><dd class="col-sm-9">${filterXSS(value)}</dd>`;
        }
    });
    return output;
}

function renderAlert(alert, expanded=false, modulesOptionsAlertReq,
                     modulesOptionsIocReq) {
  const colorSeverity = alert_severity_to_color(alert.severity.severity_name);
  const alert_color = alertStatusToColor(alert.status.status_name);
  const alert_resolution = alertResolutionToARC(alert.resolution_status, alert.alert_id);

  if (alert.owner !== null) {
      alert.owner.user_name = filterXSS(alert.owner.user_name);
  }
  alert.alert_title = alert.alert_title ? filterXSS(alert.alert_title) : t('No title provided');
  alert.alert_description = alert.alert_description ? filterXSS(alert.alert_description) : t('No description provided');
  alert.alert_source = alert.alert_source ? filterXSS(alert.alert_source) : t('No source provided');
  alert.alert_source_link = filterXSS(alert.alert_source_link);
  alert.alert_source_ref = filterXSS(alert.alert_source_ref);
  alert.alert_note = filterXSS(alert.alert_note);

  let menuOptionsHtmlAlert = '';
  const menuOptions = modulesOptionsAlertReq;
  if (menuOptions.length !== 0) {

      menuOptionsHtmlAlert = '<div class="dropdown-divider"></div>';
      for (let index in menuOptions) {
        let opt = menuOptions[index];
        menuOptionsHtmlAlert += `<a class="dropdown-item" href="javascript:void(0);" onclick='init_module_processing_alert(${alert.alert_id}, "${opt.hook_name}",`+
                    `"${opt.manual_hook_ui_name}","${opt.module_name}");return false;'><i class="fa fa-arrow-alt-circle-right mr-2"></i> ${opt.manual_hook_ui_name}</a>`
      }
  }

  const openctiIocOption = findOpenCTIIocOption(modulesOptionsIocReq);

  return `
<div class="card alert-card full-height alert-card-selectable ${alert_color}" id="alertCard-${alert.alert_id}">
  <div class="card-body">
    <div class="container-fluid">
      <div class="row">
        <div class=flex-column>
          <!-- Avatar group and tickbox -->
          
        </div>
        <div class="col">
          <!-- Alert details -->
          <div class="d-flex flex-column">
            <div class="flex-1 ml-md-4 mr-4 pt-1">
                <div class="row mb-4">
                    <div class="flex-column">
                        <div class="avatar-group ${alert.owner ? '' : 'ml-2 mr-2'}">
                            <div class="avatar-tickbox-wrapper">
                              <div class="avatar-wrapper">
                                <div class="avatar cursor-pointer">
                                  <span class="avatar-title alert-m-title alert-similarity-trigger rounded-circle bg-${colorSeverity}" data-toggle="collapse" data-target="#additionalDetails-${alert.alert_id}" >
                                    <i class="fa-solid fa-fire"></i>
                                  </span>
                                </div>
                                ${alert.owner ? get_avatar_initials(alert.owner.user_name, true, `changeAlertOwner(${alert.alert_id})`) : `<div title="${t('Assign to me')}" class="avatar avatar-sm" onclick="updateAlert(${alert.alert_id}, {alert_owner_id: userWhoami.user_id}, true);"><span class="avatar-title avatar-iris rounded-circle btn-alert-primary" style="cursor:pointer;"><i class="fa-solid fa-hand"></i></span></div>`}
                              </div>
                              <div class="tickbox" style="display:none;">
                                <input type="checkbox" class="alert-selection-checkbox" data-alert-id="${alert.alert_id}" />
                              </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-9">
                        <h6 class="text-uppercase fw-bold mb-1 mt-1 ml-3 alert-m-title alert-m-title-${colorSeverity}" data-toggle="collapse" data-target="#additionalDetails-${alert.alert_id}" onclick="fetchSmartRelations(${alert.alert_id});">
                            ${alert.alert_title}
                            <span class="text-${colorSeverity} pl-3"></span>
                            <div class="d-flex mb-3">
                               
                                <span title="${t('Alert IDs')}" class=""><small class="text-muted"><i>#${alert.alert_id} - ${alert.alert_uuid}</i></small></span>
                            </div>
                        </h6>
                    </div>
                    
                    <div class="col-xs-12 col">
                                        
                        <div class=" d-flex mt-3">
                            <div class="ml-auto">
                                <button type="button" class="btn bg-transparent btn-sm mt--4" onclick="comment_element(${alert.alert_id}, 'alerts', true)" title="${t('Comments')}">
                                  <span class="btn-label">
                                    <i class="fa-solid fa-comments"></i><span class="notification" id="object_comments_number_${alert.alert_id}">${alert.comments.length || ''}</span>
                                  </span>
                                </button>
                                <button class="btn btn-sm bg-transparent mt--4" type="button" onclick="editAlert(${alert.alert_id})"><i class="fa fa-pencil"></i></button>
                                <button class="btn bg-transparent mt--4" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                  <span aria-hidden="true"><i class="fas fa-ellipsis-v"></i></span>
                                </button>
                                <div class="dropdown-menu" role="menu">
                                  <a href="javascript:void(0)" class="dropdown-item" onclick="copyAlertLink(${alert.alert_id});return false;"><small class="fa fa-share mr-2"></small>${t('Share')}</a>
                                  <a href="javascript:void(0)" class="dropdown-item" onclick="copyMDAlertLink(${alert.alert_id});return false;"><small class="fa-brands fa-markdown mr-2"></small>${t('Markdown link')}</a>
                                  ${menuOptionsHtmlAlert}
                                  <div class="dropdown-divider"></div>
                                  <a href="javascript:void(0)" class="dropdown-item" onclick="showAlertHistory(${alert.alert_id});return false;"><small class="fa fa-clock-rotate-left mr-2"></small>${t('History')}</a>
                                  <div class="dropdown-divider"></div>
                                  <a href="javascript:void(0)" class="dropdown-item text-danger" onclick="delete_alert(${alert.alert_id});"><small class="fa fa-trash mr-2"></small>${t('Delete alert')}</a>
                                </div>
                            </div>
                        </div>          
                                        
                    </div>

                </div>
                
                <div class="float-right alert-actions mt--4">
                      <div class="dropdown ml-2 d-inline-block">
                          <button type="button" class="btn btn-alert-secondary btn-sm dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                              ${t('Enricher')}
                          </button>
                          <div class="dropdown-menu">
                              <a class="dropdown-item enricher-option" href="javascript:void(0)" data-alert-id="${alert.alert_id}" data-enricher="ioc">IoC</a>
                          </div>
                      </div>
                      <button type="button" class="btn btn-alert-primary btn-sm ml-2" onclick="mergeAlertModal(${alert.alert_id}, false);">${t('Merge')}</button>
                      
                      <div class="dropdown ml-2 d-inline-block">
                          <button type="button" class="btn btn-alert-primary btn-sm dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                              ${t('Assign')}
                          </button>
                          <div class="dropdown-menu">
                              <a class="dropdown-item" href="javascript:void(0)" onclick="updateAlert(${alert.alert_id}, {alert_owner_id: userWhoami.user_id}, true);">${t('Assign to me')}</a>
                              <a class="dropdown-item" href="javascript:void(0)" onclick="changeAlertOwner(${alert.alert_id});">${t('Assign')}</a>
                          </div>
                      </div>
                      <div class="dropdown ml-2 d-inline-block">
                          <button type="button" class="btn btn-alert-primary btn-sm dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                              ${t('Set status')}
                          </button>
                          <div class="dropdown-menu">
                              <a class="dropdown-item" href="javascript:void(0)" onclick="changeStatusAlert(${alert.alert_id}, 'New');">${t('New')}</a>
                              <a class="dropdown-item" href="javascript:void(0)" onclick="changeStatusAlert(${alert.alert_id}, 'In progress');">${t('In progress')}</a>
                              <a class="dropdown-item" href="javascript:void(0)" onclick="changeStatusAlert(${alert.alert_id}, 'Pending');">${t('Pending')}</a>
                              <a class="dropdown-item" href="javascript:void(0)" onclick="changeStatusAlert(${alert.alert_id}, 'Closed');">${t('Closed')}</a>
                              <a class="dropdown-item" href="javascript:void(0)" onclick="changeStatusAlert(${alert.alert_id}, 'Merged');">${t('Merged')}</a>
                            </div>
                      </div>
                      ${alert.status.status_name === 'Closed' ? `
                          <button type="button" class="btn btn-alert-success btn-sm ml-2" onclick="changeStatusAlert(${alert.alert_id}, 'In progress');">${t('Set in progress')}</button>
                      `: ` 
                      <button type="button" class="btn btn-alert-danger btn-sm ml-2" onclick="editAlert(${alert.alert_id}, true);">${t('Close with note')}</button>
                      <button type="button" class="btn btn-alert-danger btn-sm ml-2" onclick="changeStatusAlert(${alert.alert_id}, 'Closed');">${t('Close')}</button>
                      `}
                </div>
                <span class="mt-4">${alert.alert_description.replaceAll('\n', '<br/>').replaceAll('\t', '  ')}</span>

                

              <!-- Additional details and other content -->
              <div id="additionalDetails-${alert.alert_id}" class="collapse mt-4 ${expanded? 'show': ''} alert-collapsible">
                <div class="card-no-pd mt-2">
                    <div class="card-body">
                    <h3 class="title mb-3"><strong>${t('General info')}</strong></h3>  
                        ${alert.alert_source ? `<div class="row"><div class="col-md-3"><b>${t('Source')}:</b></div>
                        <div class="col-md-9">${alert.alert_source}</div>
                      </div>` : ''}
                      ${alert.alert_source_link ? `<div class="row mt-2">
                        <div class="col-md-3"><b>${t('Source link')}:</b></div>
                        <div class="col-md-9 copy-value">${
                            alert.alert_source_link && alert.alert_source_link.startsWith('http') 
                            ? `<a href="${alert.alert_source_link}" target="_blank" rel="noopener noreferrer">${alert.alert_source_link}</a>
                                <button class="copy-btn ml-2" data-value="${escapeHtml(alert.alert_source_link)}">
                                    <i class="fa fa-copy text-dark"></i>
                                </button>`
                            : t('No valid link provided')
                          }</div>
                      </div>` : ''}
                      ${alert.alert_source_ref ? `<div class="row mt-2">
                        <div class="col-md-3"><b>${t('Source reference')}:</b></div>
                        <div class="col-md-9 copy-value">
                            ${alert.alert_source_ref}
                            <button class="copy-btn ml-2" data-value="${escapeHtml(alert.alert_source_ref)}">
                                    <i class="fa fa-copy text-dark"></i>
                            </button>
                        </div>
                      </div>` : ''}
                      ${alert.alert_source_event_time ? `<div class="row mt-2">
                        <div class="col-md-3"><b>${t('Source event time')}:</b></div>
                        <div class="col-md-9 copy-value">
                            ${formatTime(alert.alert_source_event_time)} UTC
                            <button class="copy-btn ml-2" data-value="${formatTime(alert.alert_source_event_time)}">
                                    <i class="fa fa-copy text-dark"></i>
                            </button>
                        </div>
                      </div>` : ''}
                      ${alert.alert_creation_time ? `<div class="row mt-2">
                        <div class="col-md-3"><b>${t('IRIS creation time')}:</b></div>
                        <div class="col-md-9 copy-value">
                            ${formatTime(alert.alert_creation_time)} UTC
                            <button class="copy-btn ml-2" data-value="${formatTime(alert.alert_creation_time)}">
                                    <i class="fa fa-copy text-dark"></i>
                            </button>
                        </div>
                      </div>` : ''}
                    
                    <div class="separator-solid"></div>
                    <h3 class="title mb-3"><strong>${t('Alert note')}</strong></h3>
                    <pre id=alertNote-${alert.alert_id}>${alert.alert_note}</pre>
                    
                    <!-- Alert Context section -->
                    ${
                        alert.alert_context && Object.keys(alert.alert_context).length > 0
                            ? `<div class="separator-solid"></div><h3 class="title mt-3 mb-3"><strong>${t('Context')}</strong></h3>
                                <dl class="row">
                                ${renderNestedObject(alert.alert_context)}
                                </dl>`
                            : ''
                      }
                    
                    <div class="separator-solid"></div>
                    <h3 class="title mt-3 mb-3"><strong>${t('Relationships')}</strong></h3>
                    <button class="btn btn-sm btn-outline-dark" type="button" data-toggle="collapse" data-target="#relationsAlert-${alert.alert_id}" 
                    aria-expanded="true" aria-controls="relationsAlert-${alert.alert_id}" onclick="fetchSmartRelations(${alert.alert_id});" id="relationsAlertButton-${alert.alert_id}">${t('Toggle relations')}</button>
                    <div class="collapse mt-3 show" id="relationsAlert-${alert.alert_id}">
                        ${t("The following relationships are automatically generated by IRIS based on the alert's IOCs and assets in the system. They are an indication only and may not be accurate.")}
                        <div class="row ml-1">
                            <div class="selectgroup selectgroup-pills mt-4">
                                <label class="selectgroup-item">
                                    <input type="checkbox" name="open_alerts_${alert.alert_id}" class="selectgroup-input filter-graph-alert-checkbox" onclick="refreshAlertRelationships(${alert.alert_id});">
                                    <span class="selectgroup-button">${t('Show open alerts')}</span>
                                </label>
                                <label class="selectgroup-item">
                                    <input type="checkbox" name="closed_alerts_${alert.alert_id}" class="selectgroup-input filter-graph-alert-checkbox" onclick="refreshAlertRelationships(${alert.alert_id})">
                                    <span class="selectgroup-button">${t('Show closed alerts')}</span>
                                </label>
                                <label class="selectgroup-item">
                                    <input type="checkbox" name="open_cases_${alert.alert_id}" class="selectgroup-input filter-graph-alert-checkbox" onclick="refreshAlertRelationships(${alert.alert_id})">
                                    <span class="selectgroup-button">${t('Show open cases')}</span>
                                </label>
                                <label class="selectgroup-item">
                                    <input type="checkbox" name="closed_cases_${alert.alert_id}" class="selectgroup-input filter-graph-alert-checkbox" onclick="refreshAlertRelationships(${alert.alert_id})">
                                    <span class="selectgroup-button">${t('Show closed cases')}</span>
                                </label>
                            </div>
                            <div class="mt-4">
                                <div class="input-group ">
                                    <div class="input-group-prepend">
                                        <span class="input-group-text">${t('Nodes limit')}</span>
                                    </div>
                                    <input type="number" name="value" value="100" class="form-control" id="nbResultsGraphFilter-${alert.alert_id}" onchange="refreshAlertRelationships(${alert.alert_id})">
                                </div>
                            </div>
                            <div class="ml-2 mt-4">
                                <div class="input-group">
                                    <div class="input-group-prepend">
                                        <span class="input-group-text">${t('Lookback (days)')}</span>
                                    </div>
                                    <input type="number" name="value" value="180" class="form-control" id="daysBackGraphFilter-${alert.alert_id}" onchange="refreshAlertRelationships(${alert.alert_id})">
                                </div>
                            </div>  
                        </div>
                        <div class="row mt-4">
                                    
                        </div>
                        <div id="similarAlertsNotify-${alert.alert_id}" class="row mt-2 ml-2 text-danger"></div>
                        <div id="similarAlerts-${alert.alert_id}" class="mt-4 similar-alert-graph"></div>
                    </div>

                
                    <!-- Alert IOCs section -->
                    ${
                      alert.iocs && alert.iocs.length > 0
                          ? `<div class="separator-solid"></div><h3 class="title mb-3"><strong>${t('IOCs')}</strong></h3>
                                       <div class="table-responsive">
                                         <table class="table table-sm table-striped alert-ioc-table">
                                           <thead>
                                             <tr>
                                               <th>${t('Value')}</th>
                                               <th>${t('Description')}</th>
                                               <th>${t('Type')}</th>
                                               <th>TLP</th>
                                               <th>${t('Tags')}</th>
                                               <th>${t('Enrichment')}</th>
                                               <th></th>
                                             </tr>
                                           </thead>
                                           <tbody>
                                             ${alert.iocs
                              .map(
                                  (ioc) => `
                                                 <tr>
                                                   <td class="copy-value">
                                                        ${filterXSS(ioc.ioc_value)}
                                                        <button class="copy-btn ml-2" data-value="${filterXSS(ioc.ioc_value)}">
                                                            <i class="fa fa-copy text-dark"></i>
                                                        </button>
                                                   </td>
                                                   <td>${filterXSS(ioc.ioc_description)}</td>
                                                   <td>${ioc.ioc_type ? filterXSS(ioc.ioc_type.type_name) : '-'}</td>
                                                   <td>${filterXSS(ioc.ioc_tlp) ? ioc.ioc_tlp : '-'}</td>
                                                   <td>${ioc.ioc_tags ? ioc.ioc_tags.split(',').map((tag) => get_tag_from_data(tag, 'badge badge-pill badge-light ml-1')).join('') : ''}</td>
                                                   <td>
                                                    ${ioc.ioc_enrichment ? renderEnrichmentInline(ioc.ioc_enrichment) : ''}
                                                    ${openctiIocOption ? `
                                                    <button type="button" class="btn btn-sm btn-outline-primary mt-2"
                                                      onclick='openctiEnrichIoc(${alert.alert_id}, ${ioc.ioc_id}, "${openctiIocOption.hook_name}",
                                                      "${openctiIocOption.manual_hook_ui_name}","${openctiIocOption.module_name}");return false;'>
                                                      ${t('OpenCTI')}
                                                    </button>` : ''}
                                                    ${ioc.ioc_enrichment ? `
                                                    <button type="button" class="btn btn-primary btn-sm btn-outline-dark btn-view-enrichment mt-2" data-toggle="modal" data-target="#enrichmentModal" onclick="showEnrichment(${JSON.stringify(ioc.ioc_enrichment).replace(/"/g, '&quot;')})">
                                                      ${t('View enrichment')}
                                                    </button>` : ''}
                                                    ${!ioc.ioc_enrichment && !openctiIocOption ? '-' : ''}
                                                    </td>
                                                    <td>
                                                       <button class="btn bg-transparent" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                                          <span aria-hidden="true"><i class="fas fa-ellipsis-v"></i></span>
                                                        </button>
                                                        <div class="dropdown-menu" role="menu">
                                                        ${ modulesOptionsIocReq.length === 0 ? `<a class="dropdown-item" href="javascript:void(0);"><i class="fas fa-rocket mr-2"></i> ${t('No module available')}</a>` :
                                                          modulesOptionsIocReq.map((opt) => `
                                                                <a class="dropdown-item" href="javascript:void(0);" onclick='init_module_processing([${ioc.ioc_id}], "${opt.hook_name}","${opt.manual_hook_ui_name}","${opt.module_name}", "ioc");return false;'><i class="fas fa-rocket mr-2"></i> ${opt.manual_hook_ui_name}</a>`
                                                            ).join('')
                                                        }
                                                        </div>
                                                    </td>
                                                 </tr>`
                              )
                              .join('')}
                                           </tbody>
                                         </table>
                                       </div>`
                          : ''
                  }
                    
                    <!-- Alert assets section -->
                    ${
                    alert.assets && alert.assets.length > 0
              ? `<div class="separator-solid"></div><h3 class="title mb-3"><strong>${t('Assets')}</strong></h3>
                           <div class="table-responsive">
                             <table class="table table-sm table-striped">
                               <thead>
                                 <tr>
                                   <th>${t('Name')}</th>
                                   <th>${t('Description')}</th>
                                   <th>${t('Type')}</th>
                                   <th>${t('Domain')}</th>
                                   <th>IP</th>
                                   <th>${t('Tags')}</th>
                                   <th>${t('Enrichment')}</th>
                                 </tr>
                               </thead>
                               <tbody>
                                 ${alert.assets
                  .map(
                      (asset) => `
                                     <tr>
                                       <td class="copy-value">
                                            ${asset.asset_name ? filterXSS(asset.asset_name) : '-'}
                                            <button class="copy-btn ml-2" data-value="${asset.asset_name ? filterXSS(asset.asset_name) : '-'}">
                                                <i class="fa fa-copy text-dark"></i>
                                            </button>
                                       </td>
                                       <td>${asset.asset_name ? filterXSS(asset.asset_name) : '-'}</td>
                                       <td>${asset.asset_description ? filterXSS(asset.asset_description) : '-'}</td>
                                       <td>${asset.asset_type ? filterXSS(asset.asset_type.asset_name) : '-'}</td>
                                       <td>${asset.asset_domain ? filterXSS(asset.asset_domain) : '-'}</td>
                                       <td>${asset.asset_ip ? filterXSS(asset.asset_ip) : '-'}</td>
                                       <td>${asset.asset_tags ? asset.asset_tags.split(',').map((tag) => get_tag_from_data(tag, 'badge badge-pill badge-light ml-1')).join('') : ''}</td>
                                       <td>${asset.asset_enrichment ? `<button type="button" class="btn btn-sm btn-outline-dark btn-view-enrichment" data-toggle="modal" data-target="#enrichmentModal" onclick="showEnrichment(${JSON.stringify(asset.asset_enrichment).replace(/"/g, '&quot;')})">
                                          ${t('View enrichment')}
                                        </button>` : ''}
                                        </td>
                                     </tr>`
                  )
                  .join('')}
                               </tbody>
                             </table>
                           </div>`
              : ''
      }
                    
                    ${
          alert.alert_source_content
              ? `<div class="separator-solid"></div><h3 class="title mt-3 mb-3"><strong>${t('Raw alert')}</strong></h3>
                           <button class="btn btn-sm btn-outline-dark" type="button" data-toggle="collapse" data-target="#rawAlert-${alert.alert_id}" 
                           aria-expanded="false" aria-controls="rawAlert-${alert.alert_id}">${t('Toggle raw alert')}</button>
                           <div class="collapse mt-3" id="rawAlert-${alert.alert_id}">
                             <pre class="pre-scrollable">${filterXSS(JSON.stringify(alert.alert_source_content, null, 2))}</pre>
                           </div>`
              : ""
      }
                    
                    </div>
                  </div>
              </div>
              ${alert.cases ? `<div class='row mt-4 mb-2'>` + alert.cases.map((case_) => `
                <div class="dropdown ml-2 d-inline-block">
                      <a class="bg-transparent ml-3" title="${t('Merged in case #{id}', { id: case_ })}" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" href="javascript:void(0)">
                          <span aria-hidden="true"><i class="fa-solid fa-link"></i>#${case_}</span>
                      </a>
                      <div class="dropdown-menu">
                        <a class="dropdown-item" href="/case?cid=${case_}" target="_blank"><i class="fa-solid fa-eye mr-2"></i> ${t('View case #{id}', { id: case_ })}</a>    
                        <div class="dropdown-divider"></div>
                        <a class="dropdown-item text-danger" href="javascript:void(0)" onclick="unlinkAlertFromCase(${alert.alert_id}, ${case_})"><i class="fa-solid fa-unlink mr-2"></i>${t('Unlink alert from case #{id}', { id: case_ })}</a>
                      </div>
                </div>
              `).join('') + '</div>' : '<div class="mb-4"></div>'}
            
              <div class="alert-meta">  
                ${alert_resolution === undefined ? "": alert_resolution} 
                ${alert.status ? `<span class="badge alert-bade-status badge-pill badge-light mr-3">${alert.status.status_name}</span>` : ''}                    
                <span title="${t('Alert source event UTC time')}"><b><i class="fa-regular fa-calendar-check"></i></b>
                <small class="text-muted ml-1">${formatTime(alert.alert_source_event_time)}</small></span>
                <span title="${t('Alert severity')}"><b class="ml-3"><i class="fa-solid fa-bolt"></i></b>
                  <small class="text-muted ml-1" id="alertSeverity-${alert.alert_id}" data-severity-id="${alert.severity.severity_id}">${alert.severity.severity_name}</small></span>
                <span title="${t('Alert source')}"><b class="ml-3"><i class="fa-solid fa-cloud-arrow-down"></i></b>
                  <small class="text-muted ml-1">${filterXSS(alert.alert_source) || t('Unspecified')}</small></span>
                <span title="${t('Alert client')}"><b class="ml-3"><i class="fa-regular fa-circle-user"></i></b>
                  <small class="text-muted ml-1 mr-2">${filterXSS(alert.customer.customer_name) || t('Unspecified')}</small></span>
                ${alert.classification && alert.classification.name_expanded ? `<span class="badge badge-pill badge-light" title="${t('Classification')}" id="alertClassification-${alert.alert_id}" data-classification-id="${alert.classification.id}"><i class="fa-solid fa-shield-virus mr-1"></i>${filterXSS(alert.classification.name_expanded)}</span>`: ''}
                ${alert.alert_tags ? alert.alert_tags.split(',').map((tag) => `<span class="badge badge-pill badge-light ml-1" title="${t('Add as filter')}" style="cursor: pointer;" data-tag="${filterXSS(tag)}" onclick="addTagFilter(this);"><i class="fa fa-tag mr-1"></i>${filterXSS(tag)}</span>`).join('') + `<div style="display:none;" id="alertTags-${alert.alert_id}">${filterXSS(alert.alert_tags)}</div>` : ''}
                
              </div>

            </div>
            
            <div class="mt-auto">
              <!-- Alert actions -->
              <div class="d-flex float-right alert-actions mt--2 ml-auto">
                <button type="button" class="btn btn-sm btn-outline-secondary"
                  onclick="refreshAlert(${alert.alert_id}); return false;">
                  <i class="fa fa-rotate-right mr-1"></i> ${t('Refresh card')}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
</div>    
</div>  `;

}

function init_module_processing_alert(alert_id, hook_name, hook_ui_name, module_name, data_type) {
    let data = Object();
    data['hook_name'] = hook_name;
    data['module_name'] = module_name;
    data['hook_ui_name'] = hook_ui_name;
    data['csrf_token'] = $('#csrf_token').val();
    data['type'] = 'alert';
    data['targets'] = [alert_id];

    post_request_api("/dim/hooks/call", JSON.stringify(data), true)
    .done(function (data){
        notify_auto_api(data)
    });
}

function openctiEnrichIoc(alertId, iocId, hookName, hookUiName, moduleName) {
    const data = Object();
    data['hook_name'] = hookName;
    data['module_name'] = moduleName;
    data['hook_ui_name'] = hookUiName;
    data['csrf_token'] = $('#csrf_token').val();
    data['type'] = 'ioc';
    data['targets'] = [iocId];

    post_request_api('/dim/hooks/call', JSON.stringify(data), true)
        .done(function (resp) {
            if (notify_auto_api(resp)) {
                refreshAlert(alertId);
                setTimeout(() => refreshAlert(alertId), 2000);
            }
        });
}

let modulesOptionsAlertReq = null;
let modulesOptionsIocReq = null;

async function showAlertHistory(alertId) {
    const alertDataReq = await fetchAlert(alertId);
    if (!notify_auto_api(alertDataReq, true)) {
        return;
    }
    let alertData = alertDataReq.data;
    let entryDiv = $('#modal_alert_history_content');

    for (let entry in alertData.modification_history)  {
        let date = new Date(Math.floor(entry) * 1000);
        let dateStr = date.toLocaleString();
        let entryStr = alertData.modification_history[entry];
        entryDiv.append('<div class="row"><div class="col-3">' + dateStr + '</div><div class="col-3">' + entryStr.user + '</div><div class="col-6">'+ entryStr.action +'</div></div>');

    }

    $('#modal_alert_history').modal('show');
}

async function refreshAlert(alertId, alertData, expanded=false) {
    if (alertData === undefined) {
        const alertDataReq = await fetchAlert(alertId);
        if (!notify_auto_api(alertDataReq, true)) {
            return;
        }
        alertData = alertDataReq.data;
    }

      if (modulesOptionsAlertReq === null) {
    modulesOptionsAlertReq = await fetchModulesOptionsAlert();
    if (!notify_auto_api(modulesOptionsAlertReq, true)) {
        return;
    }
  }
  if (modulesOptionsIocReq === null) {
    modulesOptionsIocReq = await fetchModulesOptionsIoc();
    if (!notify_auto_api(modulesOptionsIocReq, true)) {
        return;
    }
  }

    const alertElement = $(`#alertCard-${alertId}`);
    const alertHtml = renderAlert(alertData, expanded, modulesOptionsAlertReq.data, modulesOptionsIocReq.data);
    alertElement.replaceWith(alertHtml);
}

async function fetchModulesOptionsAlert() {
    const response = get_request_api('/dim/hooks/options/alert/list');

    return await response;
}

async function fetchModulesOptionsIoc() {
    const response = get_request_api('/dim/hooks/options/ioc/list');

    return await response;
}

async function fetchModulesOptionsAsset() {
    const response = get_request_api('/dim/hooks/options/asset/list');

    return await response;
}


async function updateAlerts(page, per_page, filters = {}, paging=false){
  if (sortOrder === undefined) { sortOrder = 'desc'; }

  if (paging) {
      filters = getFiltersFromUrl();
  }

  filters.custom_conditions = editor.getValue();

  const alertsContainer = $('.alerts-container');
  alertsContainer.html(`<h4 class="ml-auto mr-auto">${t('Retrieving alerts...')}</h4>`);

  const filterString = objectToQueryString(filters);
  const data = await fetchAlerts(page, per_page, filterString, sortOrder).catch((error) => {
        notify_error(t('Failed to fetch alerts'));
        alertsContainer.html(`<h4 class="ml-auto mr-auto">${t('Oops error loading the alerts - Check logs')}</h4>`);
        console.error(error);
    });

  if (!notify_auto_api(data, true)) {
    return;
  }
  const alerts = data.data.alerts;

  if (modulesOptionsAlertReq === null) {
    modulesOptionsAlertReq = await fetchModulesOptionsAlert();
    if (!notify_auto_api(modulesOptionsAlertReq, true)) {
        return;
    }
  }
  if (modulesOptionsIocReq === null) {
    modulesOptionsIocReq = await fetchModulesOptionsIoc();
    if (!notify_auto_api(modulesOptionsIocReq, true)) {
        return;
    }
  }

  // Check if the selection mode is active
   const selectionModeActive = $('body').hasClass('selection-mode');
   selectionModeActive ? $('body').removeClass('selection-mode') : '';
   $('#toggle-selection-mode').text(t('Select'));
   $('body').removeClass('selection-mode');
   $('#select-deselect-all').hide();
   $('#alerts-batch-actions').hide();

  // Clear the current alerts list
  const queryParams = new URLSearchParams(window.location.search);
  const isExpanded = queryParams.get('is-expanded') === 'true';

  alertsContainer.html('');
  if (alerts.length === 0) {
    // Display "No results" message when there are no alerts
    alertsContainer.append(`<div class="ml-auto mr-auto">${t('No results')}</div>`);
  } else {

      // Add the fetched alerts to the alerts container
      alerts.forEach((alert) => {
          const alertElement = $('<div></div>');

          const alertHtml = renderAlert(alert, isExpanded, modulesOptionsAlertReq.data,
                                               modulesOptionsIocReq.data);
          alertElement.html(alertHtml);
          alertsContainer.append(alertElement);
      });
  }

  // Update the pagination links
  const currentPage = page;
  const totalPages = Math.ceil(data.data.total / per_page);
  createPagination(currentPage, totalPages, per_page, 'updateAlerts', '.pagination-container');

  // Update the URL with the filter parameters
  queryParams.set('page', page);
  queryParams.set('per_page', per_page);
  let filter_tags_info = [];

  for (const key in filters) {
    if (filters.hasOwnProperty(key)) {
      if (filters[key] === '') {
        queryParams.delete(key);
      } else {
        queryParams.set(key, filters[key]);
        filter_tags_info.push(`  
          <span class="badge badge-light">
            <i class="fa-solid fa-magnifying-glass mr-1"></i>${key}: ${filterXSS(filters[key])}
            <span class="tag-delete-alert-filter" data-filter-key="${key}" style="cursor: pointer;" title="${t('Remove filter')}"><i class="fa-solid fa-xmark ml-1"></i></span>
          </span>
        `)
      }
    }
  }

  queryParams.set('sort', sortOrder);

  history.replaceState(null, null, `?${queryParams.toString()}`);

  const totalAlertsText = data.data.total === 1 ? t('Alert') : t('Alerts');
  $('#alertsInfoFilter').text(`${data.data.total} ${totalAlertsText} ${ filterString ? `(${t('filtered')})` : '' }`);

  if (filter_tags_info) {
    $('#alertsInfoFilterTags').html(filter_tags_info.join(' + '));
    $('#alertsInfoFilterTags .tag-delete-alert-filter').on('click', function () {
      const filterKey = $(this).data('filter-key');
      delete filters[filterKey];
      queryParams.delete(filterKey);
      $(`#${filterKey}`).val('');

      resetSavedFilters(queryParams, false);

      history.replaceState(null, null, `?${queryParams.toString()}`);
      updateAlerts(page, per_page, filters);
    });
  } else {
    $('#alertsInfoFilterTags').html('');
  }

  filterString || queryParams.get('filter_id') ? $('#resetFilters').show() : $('#resetFilters').hide();

  alertsContainer.show();

  $('.copy-btn').off().on('click', function() {
      let value = $(this).data('value');
      copy_text_clipboard(value);
  });
}

$('#alertsPerPage').on('change', (e) => {
  const per_page = parseInt(e.target.value, 10);
  updateAlerts(1, per_page, undefined, sortOrder); // Update the alerts list with the new 'per_page' value and reset to the first page
});


$('#orderAlertsBtn').on('click', function () {
  sortOrder = sortOrder === 'desc' ? 'asc' : 'desc';
  const iconClass = sortOrder === 'desc' ? 'fas fa-arrow-up-short-wide' : 'fas fa-arrow-up-wide-short';

  $('#orderAlertsBtn i').attr('class', iconClass);

  const queryParams = new URLSearchParams(window.location.search);
  let page_number = parseInt(queryParams.get('page'));
  let per_page = parseInt(queryParams.get('per_page'));


  const formData = new FormData($('#alertFilterForm')[0]);
  const filters = Object.fromEntries(formData.entries());

  updateAlerts(page_number, per_page, filters);
});

function refreshAlerts(){
    const queryParams = new URLSearchParams(window.location.search);
    let page_number = parseInt(queryParams.get('page'));
    let per_page = parseInt(queryParams.get('per_page'));

    const formData = new FormData($('#alertFilterForm')[0]);
    const filters = Object.fromEntries(formData.entries());

    filters.custom_conditions = editor.getValue();

    updateAlerts(page_number, per_page, filters)
        .then(() => {
            notify_success(t('Refreshed'));
            $('#newAlertsBadge').text(0).hide();
        });
}

function toggleCollapseAllAlerts() {
    const toggleAllBtn = $('#toggleAllAlertsBtn');
    const isExpanded = toggleAllBtn.data('is-expanded') || false;

    collapseAlerts(!isExpanded);

    const queryParams = new URLSearchParams(window.location.search);
    queryParams.set('is-expanded', !isExpanded);
    window.history.replaceState(null, '', '?' + queryParams.toString());
}

function collapseAlerts(isExpanded) {
    const alertsContainer = $('.alert-collapsible');
    const toggleAllBtn = $('#toggleAllAlertsBtn');

    if (isExpanded) {
        alertsContainer.collapse('show');
        toggleAllBtn.text(t('Collapse all'));
        toggleAllBtn.data('is-expanded', true);
    } else {
        alertsContainer.collapse('hide');
        toggleAllBtn.text(t('Expand all'));
        toggleAllBtn.data('is-expanded', false);
    }
}

$('#alertFilterForm').on('submit', (e) => {
  e.preventDefault();

  // Get the filter values from the form
  const formData = new FormData(e.target);
  const filters = Object.fromEntries(formData.entries());

  const queryParams = new URLSearchParams(window.location.search);
  let per_page = parseInt(queryParams.get('per_page'));
  if (!per_page) {
      per_page = 10;
  }

  // Update the alerts list with the new filters and reset to the first page
  updateAlerts(1, per_page, filters);
});

$('#resetFilters').on('click', function () {
  const form = $('#alertFilterForm');

    // Reset all input fields
    form.find('input, select').each((_, element) => {
        if (element.type === 'checkbox') {
          $(element).prop('checked', false);
        } else {
          $(element).val('');
        }
    });

    editor.setValue("", 1);
    // Reset the saved filters dropdown
    resetSavedFilters(null);

  // Trigger the form submit event to fetch alerts with the updated filters
  form.trigger('submit');
});

function resetSavedFilters(queryParams = null, replaceState = true) {
    if (queryParams === null || queryParams === undefined) {
        queryParams = new URLSearchParams(window.location.search);
    }
    queryParams.delete('filter_id');
    if (replaceState) {
        window.history.replaceState(null, null, `?${queryParams.toString()}`);
    }
    $('#savedFilters').selectpicker('val', '');

    return queryParams;
}


let enrichmentAceEditor = null;

function showEnrichment(enrichment) {
    const summaryEl = document.getElementById('enrichmentSummary');
    if (summaryEl) {
        summaryEl.innerHTML = renderEnrichmentSummary(enrichment);
    }

    const ace = get_new_ace_editor('enrichmentData', null,
        null, null, null, true, false);
    ace.session.setMode("ace/mode/json");
    ace.setValue(JSON.stringify(enrichment, null, 4), -1);
    enrichmentAceEditor = ace;
    setEnrichmentView('summary');
}

function setEnrichmentView(mode) {
    const summaryEl = $('#enrichmentSummary');
    const dataEl = $('#enrichmentData');
    const btnSummary = $('#enrichmentShowSummary');
    const btnRaw = $('#enrichmentShowRaw');

    if (mode === 'raw') {
        summaryEl.hide();
        dataEl.show();
        btnSummary.removeClass('btn-primary').addClass('btn-outline-primary');
        btnRaw.removeClass('btn-outline-secondary').addClass('btn-secondary');
        if (enrichmentAceEditor) {
            setTimeout(() => enrichmentAceEditor.resize(), 0);
        }
        return;
    }

    summaryEl.show();
    dataEl.hide();
    btnSummary.removeClass('btn-outline-primary').addClass('btn-primary');
    btnRaw.removeClass('btn-secondary').addClass('btn-outline-secondary');
}

function renderEnrichmentSummary(enrichment) {
    if (!enrichment || typeof enrichment !== 'object') {
        return `<div class="alert alert-secondary mb-0">${t('No enrichment data available.')}</div>`;
    }

    if (enrichment.opencti) {
        return renderOpenCTISummary(enrichment.opencti);
    }

    return `<div class="alert alert-secondary mb-0">${t('No summary available for this enrichment.')}</div>`;
}

function getOpenCTIMatchInfo(opencti) {
    const toNumber = (value) => {
        const parsed = Number(value);
        return Number.isNaN(parsed) ? 0 : parsed;
    };

    if (opencti && opencti.schema_version === '2.1') {
        const results = opencti.results || {};
        const observables = results.observables || {};
        const indicators = results.indicators || {};
        const rawObservables = toNumber(observables.raw_count);
        const rawIndicators = toNumber(indicators.raw_count);
        const matchedObservables = toNumber(observables.matched_count);
        const matchedIndicators = toNumber(indicators.matched_count);
        const modeValue = opencti.meta && opencti.meta.ioc && opencti.meta.ioc.match_mode
            ? String(opencti.meta.ioc.match_mode).toLowerCase()
            : 'exact';
        const mode = modeValue === 'fuzzy' ? 'fuzzy' : 'exact';

        return {
            observablesCount: matchedObservables,
            indicatorsCount: matchedIndicators,
            found: (matchedObservables + matchedIndicators) > 0,
            mode,
            rawTotal: rawObservables + rawIndicators,
            filteredTotal: matchedObservables + matchedIndicators
        };
    }

    const observablesCount = toNumber(opencti && opencti.observables && opencti.observables.count);
    const indicatorsCount = toNumber(opencti && opencti.indicators && opencti.indicators.count);
    const match = opencti && opencti.match ? opencti.match : null;

    if (!match) {
        return {
            observablesCount,
            indicatorsCount,
            found: (observablesCount + indicatorsCount) > 0,
            mode: null,
            rawTotal: null,
            filteredTotal: observablesCount + indicatorsCount
        };
    }

    const rawObservables = match.raw_counts && match.raw_counts.observables !== undefined
        ? toNumber(match.raw_counts.observables)
        : observablesCount;
    const rawIndicators = match.raw_counts && match.raw_counts.indicators !== undefined
        ? toNumber(match.raw_counts.indicators)
        : indicatorsCount;
    const filteredObservables = match.filtered_counts && match.filtered_counts.observables !== undefined
        ? toNumber(match.filtered_counts.observables)
        : observablesCount;
    const filteredIndicators = match.filtered_counts && match.filtered_counts.indicators !== undefined
        ? toNumber(match.filtered_counts.indicators)
        : indicatorsCount;
    const modeValue = match.mode ? String(match.mode).toLowerCase() : 'exact';
    const mode = modeValue === 'fuzzy' ? 'fuzzy' : 'exact';

    return {
        observablesCount: filteredObservables,
        indicatorsCount: filteredIndicators,
        found: (filteredObservables + filteredIndicators) > 0,
        mode,
        rawTotal: rawObservables + rawIndicators,
        filteredTotal: filteredObservables + filteredIndicators
    };
}

function renderEnrichmentInline(enrichment) {
    if (!enrichment || typeof enrichment !== 'object') {
        return '';
    }
    if (!enrichment.opencti) {
        return '';
    }

    const opencti = enrichment.opencti;
    const matchInfo = getOpenCTIMatchInfo(opencti);
    const observablesCount = matchInfo.observablesCount;
    const indicatorsCount = matchInfo.indicatorsCount;
    const found = matchInfo.found;
    const matchBadge = matchInfo.mode
        ? `<span class="badge badge-info">${matchInfo.mode === 'fuzzy' ? t('Fuzzy') : t('Exact')}</span>`
        : '';
    const exactBadge = matchInfo.mode && matchInfo.rawTotal !== null && matchInfo.rawTotal !== matchInfo.filteredTotal
        ? `<span class="badge badge-secondary">${t('Exact {matched} of {raw}', {matched: matchInfo.filteredTotal, raw: matchInfo.rawTotal})}</span>`
        : '';

    const scoreInfo = computeOpenCTIScore(opencti);
    const scoreValue = scoreInfo.score !== null ? scoreInfo.score : null;
    const severity = scoreValue !== null ? openctiScoreToSeverity(scoreValue) : 'Unknown';
    const severityLabel = t(severity);
    const severityClass = openctiSeverityToBadgeClass(severity);
    const scoreLabel = scoreValue !== null ? t('Score {score}', {score: scoreValue}) : t('Score N/A');
    const relationsCount = Number((opencti && opencti.relations && opencti.relations.count) || 0);

    return `
        <div class="ioc-enrichment-inline">
            <span class="badge ${found ? 'badge-danger' : 'badge-success'}">
                ${found ? t('Found') : t('Not found')}
            </span>
            ${matchBadge}
            ${exactBadge}
            <span class="badge badge-light">${scoreLabel}</span>
            <span class="badge ${severityClass}">${severityLabel}</span>
            <span class="badge badge-secondary">${t('Indicators')} ${indicatorsCount}</span>
            <span class="badge badge-secondary">${t('Observables')} ${observablesCount}</span>
            ${relationsCount > 0 ? `<span class="badge badge-secondary">${t('Relations')} ${relationsCount}</span>` : ''}
        </div>
    `;
}

function renderOpenCTIMatchedEntities(opencti, key) {
    const results = opencti && opencti.results ? opencti.results : null;
    const section = results && results[key] ? results[key] : null;
    if (!section || !Array.isArray(section.matched) || section.matched.length === 0) {
        return '';
    }
    const title = key === 'observables' ? t('Matched Observables') : t('Matched Indicators');
    const detailKey = key === 'observables' ? 'matched_fields' : 'matched_literals';
    const detailLabel = key === 'observables' ? t('fields') : t('literals');
    const items = section.matched.slice(0, 5).map((entry) => {
        const node = entry && entry.node ? entry.node : null;
        let labelValue = openctiEntityLabel(node);
        if (labelValue === '-' && node && node.pattern) {
            labelValue = node.pattern;
        }
        const label = escapeHtml(String(labelValue));
        const details = entry && Array.isArray(entry[detailKey]) ? entry[detailKey] : [];
        const detailsText = details.length
            ? details.map((item) => escapeHtml(String(item))).join(', ')
            : t('Fuzzy');
        const score = node && node.x_opencti_score !== undefined
            ? t('score {score}', {score: escapeHtml(String(node.x_opencti_score))})
            : '';
        const confidence = node && node.confidence !== undefined
            ? t('confidence {confidence}', {confidence: escapeHtml(String(node.confidence))})
            : '';
        const meta = [score, confidence].filter(Boolean).join(' ');
        const metaHtml = meta ? ` <span class="text-muted">${meta}</span>` : '';
        return `<li>${label} <span class="text-muted">(${detailLabel}: ${detailsText})</span>${metaHtml}</li>`;
    }).join('');

    return `
        <div class="row mt-2">
            <div class="col-md-3"><strong>${title}</strong></div>
            <div class="col-md-9"><ul class="mb-0">${items}</ul></div>
        </div>
    `;
}

function renderOpenCTISummary(opencti) {
    if (opencti && opencti.schema_version === '2.1') {
        return renderOpenCTISummaryV21(opencti);
    }
    return renderOpenCTISummaryLegacy(opencti);
}

function renderOpenCTISummaryV21(opencti) {
    const matchInfo = getOpenCTIMatchInfo(opencti);
    const observablesCount = matchInfo.observablesCount;
    const indicatorsCount = matchInfo.indicatorsCount;
    const found = matchInfo.found;
    const matchBadge = matchInfo.mode
        ? `<span class="badge badge-info ml-2">${matchInfo.mode === 'fuzzy' ? t('Fuzzy') : t('Exact')}</span>`
        : '';
    const exactBadge = matchInfo.mode && matchInfo.rawTotal !== null && matchInfo.rawTotal !== matchInfo.filteredTotal
        ? `<span class="badge badge-secondary ml-2">${t('Exact {matched} of {raw}', {matched: matchInfo.filteredTotal, raw: matchInfo.rawTotal})}</span>`
        : '';

    const scoreInfo = computeOpenCTIScore(opencti);
    const scoreValue = scoreInfo.score !== null ? scoreInfo.score : null;
    const severity = scoreValue !== null ? openctiScoreToSeverity(scoreValue) : 'Unknown';
    const scoreLabel = scoreValue !== null ? `${scoreValue} (${scoreInfo.source})` : t('N/A');

    const meta = opencti && opencti.meta ? opencti.meta : {};
    const iocMeta = meta.ioc || {};
    const checkedAt = meta.checked_at ? formatTime(meta.checked_at) : '-';
    const searchValue = iocMeta.value ? escapeHtml(String(iocMeta.value)) : '-';
    const iocType = iocMeta.type ? escapeHtml(String(iocMeta.type)) : '-';
    const matchMode = iocMeta.match_mode ? escapeHtml(String(iocMeta.match_mode)) : '-';
    const normalized = iocMeta.normalized ? escapeHtml(String(iocMeta.normalized)) : '-';
    const defanged = iocMeta.defanged === undefined ? '-' : (iocMeta.defanged ? t('Yes') : t('No'));
    const openctiUrlRaw = (meta.source && meta.source.opencti_url)
        ? String(meta.source.opencti_url)
        : '';
    const openctiUrl = openctiUrlRaw
        ? `<a href="${escapeHtml(openctiUrlRaw)}" target="_blank" rel="noopener noreferrer">${escapeHtml(openctiUrlRaw)}</a>`
        : '-';

    const relationsJson = opencti && opencti.relations ? JSON.stringify(opencti.relations).replace(/"/g, '&quot;') : null;
    const searchValueRaw = iocMeta.value ? iocMeta.value : '';
    const searchValueArg = JSON.stringify(searchValueRaw).replace(/"/g, '&quot;');
    const relationsAvailable = opencti && opencti.relations && Array.isArray(opencti.relations.items) && opencti.relations.items.length > 0;
    const relationsButton = relationsAvailable
        ? `<button type="button" class="btn btn-sm btn-outline-primary mt-2" data-toggle="modal" data-target="#openctiRelationsModal"\n             onclick="showOpenCTIRelationsGraph(${relationsJson}, ${searchValueArg});">${t('View relations graph')}</button>`
        : '';

    const relationsBlock = renderOpenCTIRelations(opencti);
    const indicatorsBlock = renderOpenCTIMatchedEntities(opencti, 'indicators');
    const observablesBlock = renderOpenCTIMatchedEntities(opencti, 'observables');

    let errorsHtml = '';
    if (opencti && Array.isArray(opencti.errors) && opencti.errors.length > 0) {
        const errText = opencti.errors.map((item) => escapeHtml(JSON.stringify(item))).join('<br/>');
        errorsHtml = `<div class="alert alert-warning mt-3 mb-0">${t('Errors:')}<br/>${errText}</div>`;
    }

    return `
        <div class="card">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3"><strong>${t('OpenCTI')}</strong></div>
                    <div class="col-md-9">${openctiUrl}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('IOC')}</strong></div>
                    <div class="col-md-9">${searchValue} <span class="badge badge-light ml-2">${iocType}</span></div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Checked at')}</strong></div>
                    <div class="col-md-9">${escapeHtml(String(checkedAt))}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Match mode')}</strong></div>
                    <div class="col-md-9">${matchMode}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Normalized')}</strong></div>
                    <div class="col-md-9">${normalized}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Defanged')}</strong></div>
                    <div class="col-md-9">${defanged}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Presence')}</strong></div>
                    <div class="col-md-9">
                        <span class="badge ${found ? 'badge-danger' : 'badge-success'}">
                            ${found ? t('Found in OpenCTI') : t('Not found')}
                        </span>
                        ${matchBadge}
                        ${exactBadge}
                    </div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Indicators')}</strong></div>
                    <div class="col-md-9">${indicatorsCount}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Observables')}</strong></div>
                    <div class="col-md-9">${observablesCount}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Score')}</strong></div>
                    <div class="col-md-9">${scoreLabel}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Criticality')}</strong></div>
                    <div class="col-md-9">${t(severity)}</div>
                </div>
                ${relationsButton ? `<div class="row mt-2"><div class="col-md-3"></div><div class="col-md-9">${relationsButton}</div></div>` : ''}
                ${relationsBlock}
                ${indicatorsBlock}
                ${observablesBlock}
                ${errorsHtml}
            </div>
        </div>
    `;
}

function renderOpenCTISummaryLegacy(opencti) {
    const matchInfo = getOpenCTIMatchInfo(opencti);
    const observablesCount = matchInfo.observablesCount;
    const indicatorsCount = matchInfo.indicatorsCount;
    const found = matchInfo.found;
    const matchBadge = matchInfo.mode
        ? `<span class="badge badge-info ml-2">${matchInfo.mode === 'fuzzy' ? t('Fuzzy') : t('Exact')}</span>`
        : '';
    const exactBadge = matchInfo.mode && matchInfo.rawTotal !== null && matchInfo.rawTotal !== matchInfo.filteredTotal
        ? `<span class="badge badge-secondary ml-2">${t('Exact {matched} of {raw}', {matched: matchInfo.filteredTotal, raw: matchInfo.rawTotal})}</span>`
        : '';

    const scoreInfo = computeOpenCTIScore(opencti);
    const scoreValue = scoreInfo.score !== null ? scoreInfo.score : null;
    const severity = scoreValue !== null ? openctiScoreToSeverity(scoreValue) : 'Unknown';
    const scoreLabel = scoreValue !== null ? `${scoreValue} (${scoreInfo.source})` : t('N/A');

    const checkedAt = (opencti && opencti.checked_at) ? formatTime(opencti.checked_at) : '-';
    const searchValue = (opencti && opencti.search_value) ? escapeHtml(String(opencti.search_value)) : '-';
    const iocType = (opencti && opencti.ioc_type) ? escapeHtml(String(opencti.ioc_type)) : '-';
    const openctiUrlRaw = (opencti && opencti.source && opencti.source.opencti_url)
        ? String(opencti.source.opencti_url)
        : '';
    const openctiUrl = openctiUrlRaw
        ? `<a href="${escapeHtml(openctiUrlRaw)}" target="_blank" rel="noopener noreferrer">${escapeHtml(openctiUrlRaw)}</a>`
        : '-';

    const relationsJson = opencti && opencti.relations ? JSON.stringify(opencti.relations).replace(/"/g, '&quot;') : null;
    const searchValueRaw = opencti && opencti.search_value ? opencti.search_value : '';
    const searchValueArg = JSON.stringify(searchValueRaw).replace(/"/g, '&quot;');
    const relationsAvailable = opencti && opencti.relations && Array.isArray(opencti.relations.items) && opencti.relations.items.length > 0;
    const relationsButton = relationsAvailable
        ? `<button type="button" class="btn btn-sm btn-outline-primary mt-2" data-toggle="modal" data-target="#openctiRelationsModal"\n             onclick="showOpenCTIRelationsGraph(${relationsJson}, ${searchValueArg});">${t('View relations graph')}</button>`
        : '';

    const relationsBlock = renderOpenCTIRelations(opencti);
    const indicatorsBlock = renderOpenCTIEntities(opencti, 'indicators', t('Indicators'));
    const observablesBlock = renderOpenCTIEntities(opencti, 'observables', t('Observables'));

    let errorsHtml = '';
    if (opencti && Array.isArray(opencti.errors) && opencti.errors.length > 0) {
        const errText = opencti.errors.map((item) => escapeHtml(JSON.stringify(item))).join('<br/>');
        errorsHtml = `<div class="alert alert-warning mt-3 mb-0">${t('Errors:')}<br/>${errText}</div>`;
    }

    const legacyBanner = `<div class=\"alert alert-info mb-3\">${t('Legacy OpenCTI data (v2.0). Re-enrich to see match details.')}</div>`;

    return `
        <div class="card">
            <div class="card-body">
                ${legacyBanner}
                <div class="row">
                    <div class="col-md-3"><strong>${t('OpenCTI')}</strong></div>
                    <div class="col-md-9">${openctiUrl}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('IOC')}</strong></div>
                    <div class="col-md-9">${searchValue} <span class="badge badge-light ml-2">${iocType}</span></div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Checked at')}</strong></div>
                    <div class="col-md-9">${escapeHtml(String(checkedAt))}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Presence')}</strong></div>
                    <div class="col-md-9">
                        <span class="badge ${found ? 'badge-danger' : 'badge-success'}">
                            ${found ? t('Found in OpenCTI') : t('Not found')}
                        </span>
                        ${matchBadge}
                        ${exactBadge}
                    </div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Indicators')}</strong></div>
                    <div class="col-md-9">${indicatorsCount}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Observables')}</strong></div>
                    <div class="col-md-9">${observablesCount}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Score')}</strong></div>
                    <div class="col-md-9">${scoreLabel}</div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-3"><strong>${t('Criticality')}</strong></div>
                    <div class="col-md-9">${t(severity)}</div>
                </div>
                ${relationsButton ? `<div class="row mt-2"><div class="col-md-3"></div><div class="col-md-9">${relationsButton}</div></div>` : ''}
                ${relationsBlock}
                ${indicatorsBlock}
                ${observablesBlock}
                ${errorsHtml}
            </div>
        </div>
    `;
}

function computeOpenCTIScore(opencti) {
    const scores = [];
    const addScore = (value) => {
        if (value === null || value === undefined) {
            return;
        }
        const parsed = Number(value);
        if (!Number.isNaN(parsed)) {
            scores.push(parsed);
        }
    };

    const nodes = [];
    if (opencti && opencti.schema_version === '2.1') {
        const results = opencti.results || {};
        const collect = (section) => {
            if (!section || !Array.isArray(section.matched)) {
                return;
            }
            section.matched.forEach((entry) => {
                if (entry && entry.node) {
                    nodes.push(entry.node);
                }
            });
        };
        collect(results.indicators);
        collect(results.observables);
    } else {
        if (opencti && opencti.indicators && Array.isArray(opencti.indicators.nodes)) {
            nodes.push(...opencti.indicators.nodes);
        }
        if (opencti && opencti.observables && Array.isArray(opencti.observables.nodes)) {
            nodes.push(...opencti.observables.nodes);
        }
    }

    nodes.forEach((node) => {
        if (!node) {
            return;
        }
        addScore(node.x_opencti_score);
        addScore(node.confidence);
        addScore(node.score);
    });

    if (scores.length === 0) {
        return { score: null, source: 'n/a' };
    }

    return { score: Math.max(...scores), source: 'max' };
}

function openctiScoreToSeverity(score) {
    if (score >= 80) {
        return 'Critical';
    }
    if (score >= 60) {
        return 'High';
    }
    if (score >= 30) {
        return 'Medium';
    }
    if (score > 0) {
        return 'Low';
    }
    return 'Unknown';
}

function openctiSeverityToBadgeClass(severity) {
    switch (severity) {
        case 'Critical':
            return 'badge-danger';
        case 'High':
            return 'badge-warning';
        case 'Medium':
            return 'badge-info';
        case 'Low':
            return 'badge-secondary';
        default:
            return 'badge-light';
    }
}

function findOpenCTIIocOption(options) {
    if (!Array.isArray(options)) {
        return null;
    }
    for (let i = 0; i < options.length; i += 1) {
        const opt = options[i];
        if (opt && opt.module_name === 'UTMN_opencti_module' && opt.hook_name === 'on_manual_trigger_ioc') {
            return opt;
        }
    }
    return null;
}

function openctiEntityLabel(entity) {
    if (!entity) {
        return '-';
    }
    return entity.name || entity.observable_value || entity.value || entity.standard_id || entity.id || '-';
}

function renderOpenCTIRelations(opencti) {
    if (!opencti || !opencti.relations) {
        return '';
    }
    if (!Array.isArray(opencti.relations.items)) {
        return '';
    }
    const items = opencti.relations.items.slice(0, 5);
    const hasErrors = Array.isArray(opencti.relations.errors) && opencti.relations.errors.length > 0;

    const list = items.map((rel) => {
        const relType = rel && rel.relationship_type ? escapeHtml(rel.relationship_type) : t('related-to');
        const fromLabel = escapeHtml(openctiEntityLabel(rel ? rel.from : null));
        const toLabel = escapeHtml(openctiEntityLabel(rel ? rel.to : null));
        return `<li>${relType}: ${fromLabel} -> ${toLabel}</li>`;
    }).join('');

    const errorsHtml = hasErrors
        ? `<div class="alert alert-warning mt-2 mb-0">${t('Relations errors: {errors}', {errors: escapeHtml(JSON.stringify(opencti.relations.errors))})}</div>`
        : '';

    if (items.length === 0 && !hasErrors) {
        return '';
    }

    return `
        <div class="row mt-3">
            <div class="col-md-3"><strong>${t('Relations')}</strong></div>
            <div class="col-md-9">
                ${items.length > 0 ? `<ul class="mb-0">${list}</ul>` : ''}
                ${errorsHtml}
            </div>
        </div>
    `;
}

function renderOpenCTIEntities(opencti, key, title) {
    if (!opencti || !opencti[key] || !Array.isArray(opencti[key].nodes)) {
        return '';
    }
    const nodes = opencti[key].nodes.slice(0, 3);
    if (nodes.length === 0) {
        return '';
    }
    const list = nodes.map((node) => {
        const label = escapeHtml(openctiEntityLabel(node));
        const score = node && node.x_opencti_score !== undefined
            ? t('score {score}', {score: node.x_opencti_score})
            : '';
        const confidence = node && node.confidence !== undefined
            ? t('confidence {confidence}', {confidence: node.confidence})
            : '';
        const pattern = key === 'indicators' && node && node.pattern
            ? t('pattern {pattern}', {pattern: truncateText(node.pattern, 80)})
            : '';
        const meta = [score, confidence, pattern].filter((item) => item).join(', ');
        return `<li>${label}${meta ? ` (${escapeHtml(meta)})` : ''}</li>`;
    }).join('');

    return `
        <div class="row mt-3">
            <div class="col-md-3"><strong>${title}</strong></div>
            <div class="col-md-9">
                <ul class="mb-0">${list}</ul>
            </div>
        </div>
    `;
}

let openctiRelationsNetwork = null;

function showOpenCTIRelationsGraph(relations, searchValue) {
    const infoEl = document.getElementById('openctiRelationsInfo');
    const graphEl = document.getElementById('openctiRelationsGraph');
    if (!graphEl) {
        return;
    }

    if (infoEl) {
        infoEl.textContent = searchValue ? t('IOC: {ioc}', {ioc: searchValue}) : '';
    }

    if (!relations || !Array.isArray(relations.items) || relations.items.length === 0) {
        graphEl.innerHTML = `<div class="alert alert-secondary">${t('No relations to display.')}</div>`;
        return;
    }

    const nodesMap = new Map();
    const edges = [];
    let edgeId = 1;

    relations.items.forEach((rel) => {
        if (!rel) {
            return;
        }
        const from = rel.from || {};
        const to = rel.to || {};
        const fromId = from.id;
        const toId = to.id;
        if (!fromId || !toId) {
            return;
        }

        if (!nodesMap.has(fromId)) {
            nodesMap.set(fromId, {
                id: fromId,
                label: `${openctiEntityLabel(from)}\\n(${from.entity_type || t('Entity')})`,
                group: from.entity_type || t('Entity')
            });
        }
        if (!nodesMap.has(toId)) {
            nodesMap.set(toId, {
                id: toId,
                label: `${openctiEntityLabel(to)}\\n(${to.entity_type || t('Entity')})`,
                group: to.entity_type || t('Entity')
            });
        }

        edges.push({
            id: `rel-${edgeId++}`,
            from: fromId,
            to: toId,
            arrows: 'to',
            label: rel.relationship_type || t('related-to'),
            font: { align: 'middle', size: 10 }
        });
    });

    const nodes = new vis.DataSet(Array.from(nodesMap.values()));
    const edgesSet = new vis.DataSet(edges);
    const data = { nodes: nodes, edges: edgesSet };
    const options = {
        nodes: {
            shape: 'dot',
            size: 12,
            font: { size: 12 }
        },
        edges: {
            smooth: true,
            arrows: { to: { enabled: true, scaleFactor: 0.7 } }
        },
        physics: {
            stabilization: true
        },
        layout: {
            improvedLayout: true
        }
    };

    if (openctiRelationsNetwork) {
        openctiRelationsNetwork.destroy();
        openctiRelationsNetwork = null;
    }

    openctiRelationsNetwork = new vis.Network(graphEl, data, options);
}

$(document).on('hidden.bs.modal', '#openctiRelationsModal', function () {
    if (openctiRelationsNetwork) {
        openctiRelationsNetwork.destroy();
        openctiRelationsNetwork = null;
    }
    const graphEl = document.getElementById('openctiRelationsGraph');
    if (graphEl) {
        graphEl.innerHTML = '';
    }
});

$(document).on('click', '#enrichmentShowSummary', function () {
    setEnrichmentView('summary');
});

$(document).on('click', '#enrichmentShowRaw', function () {
    setEnrichmentView('raw');
});

function truncateText(text, maxLen) {
    if (!text) {
        return '';
    }
    const value = String(text);
    if (value.length <= maxLen) {
        return value;
    }
    return value.slice(0, Math.max(0, maxLen - 3)) + '...';
}

function delete_alert(alert_id) {
    do_deletion_prompt(t('Are you sure you want to delete alert #{id}?', { id: alert_id }), true)
        .then((doDelete) => {
            if (doDelete) {
                post_request_api(`/alerts/delete/${alert_id}`)
                    .then((data) => {
                        if (notify_auto_api(data)) {
                            setFormValuesFromUrl();
                        }
                    });
            }
        });
}

function getAlertResolutionName(alert_id) {
    return $(`#alertResolution-${alert_id}`).data('value');
}

async function editAlert(alert_id, close=false) {

    const alertTag = $('#editAlertTags');
    const confirmAlertEdition = $('#confirmAlertEdition');

    alertTag.val($(`#alertTags-${alert_id}`).text())
    set_suggest_tags(`editAlertTags`);
    $('#editAlertNote').val($(`#alertNote-${alert_id}`).text());

    let alert_resolution = getAlertResolutionName(alert_id);
    if (alert_resolution === '') {
        alert_resolution = 'unknown';
    }

    // Uncheck all radio buttons
    $(`input[type='radio'][name='resolutionStatus']`).prop('checked', false);

    $(`input[type='radio'][name='resolutionStatus'][value='${alert_resolution}']`).prop('checked', true);

    if (close) {
        confirmAlertEdition.text(t('Close alert'));
        $('.alert-edition-part').hide();
        $('#closeAlertModalLabel').text(t('Close alert #{id}', { id: alert_id }));
    } else {
        $('.alert-edition-part').show();
        $('#closeAlertModalLabel').text(t('Edit alert #{id}', { id: alert_id }));
        confirmAlertEdition.text(t('Save'))
    }

    fetchSelectOptions('editAlertClassification', selectsConfig['alert_classification_id']).then(() => {
      $('#editAlertClassification').val($(`#alertClassification-${alert_id}`).data('classification-id'));
    }).catch(error => {
      console.error(error);
    });

    fetchSelectOptions('editAlertSeverity', selectsConfig['alert_severity_id']).then(() => {
      $('#editAlertSeverity').val($(`#alertSeverity-${alert_id}`).data('severity-id'));
    }).catch(error => {
      console.error(error);
    });

   $('#editAlertModal').modal('show');

    confirmAlertEdition.off('click').on('click', function () {
        let alert_note = $('#editAlertNote').val();
        let alert_tags = alertTag.val();

        let data = {
          alert_note: alert_note,
          alert_tags: alert_tags,
          alert_resolution_status_id: getAlertResolutionId($("input[type='radio'][name='resolutionStatus']:checked").val()),
          alert_severity_id: $('#editAlertSeverity').val(),
        };

        let alert_classification_id = $('#editAlertClassification').val();
        if (alert_classification_id)
            data['alert_classification_id'] = alert_classification_id;

        if (close) {
            data['alert_status_id'] = getAlertStatusId('Closed');
        }

        updateAlert(alert_id, data, true, true)
            .then(() => {
                $('#editAlertModal').modal('hide');
            });
    });
}

function closeBatchAlerts() {
    const alertTag = $('#editAlertTags');
    const confirmAlertEdition = $('#confirmAlertEdition');
    $('#editAlertNote').val('');
    alertTag.val('');

    confirmAlertEdition.text(t('Close alerts'));
    $('.alert-edition-part').hide();
    $('#closeAlertModalLabel').text(t('Close multiple alerts'));

    $('#editAlertModal').modal('show');

    confirmAlertEdition.off('click').on('click', function () {
        let alert_note = $('#editAlertNote').val();
        let alert_tags = alertTag.val();

        let data = {
          alert_note: alert_note,
          alert_tags: alert_tags,
          alert_resolution_status_id: getAlertResolutionId($("input[type='radio'][name='resolutionStatus']:checked").val()),
        };

        if (close) {
            data['alert_status_id'] = getAlertStatusId('Closed');
        }

        updateBatchAlerts(data)
            .then(() => {
                $('#editAlertModal').modal('hide');
            });
    });

}

async function fetchSavedFilters() {
    const url = '/filters/alerts/list';
    return get_request_api(url)
        .then((data) => {
            if (notify_auto_api(data, true)) {
                const savedFiltersDropdown = $('#savedFiltersDropdown');

                savedFiltersDropdown.empty();

                let dropdownHtml = `
                    <select class="selectpicker ml-2" data-style="btn-sm" data-live-search="true" title="${t('Select preset filter')}" id="savedFilters">
                `;

                data.data.forEach(filter => {
                    let filter_name = filterXSS(filter.filter_name);
                    dropdownHtml += `
                                <option value="${filter.filter_id}" data-content='<div class="d-flex align-items-center"><span>${filter_name} ${filter.filter_is_private ? `(${t('private')})` : ''}</span><div class="trash-wrapper hidden-trash"><i class="fas fa-trash delete-filter text-danger" id="dropfilter-id-${filter.filter_id}" title="${t('Delete filter')}"></i></div></div>'>${filter_name}</option>
                    `;
                });

                dropdownHtml += '</select>';

                savedFiltersDropdown.append(dropdownHtml);

                // Initialize the bootstrap-select component
                $('#savedFilters').selectpicker();

                // Add the event listener after the selectpicker is loaded
                $('#savedFilters').on('shown.bs.select', function () {
                    $('.trash-wrapper').removeClass('hidden-trash');
                    $('.delete-filter').off().on('click', function (event) {
                        event.preventDefault();
                        event.stopPropagation();

                        const filterId = $(this).attr('id').split('-')[2];

                        if (!filterId) return;

                        do_deletion_prompt(t('Are you sure you want to delete filter #{id}?', { id: filterId }), true)
                            .then((do_delete) => {
                                if (!do_delete) return;
                                const url = `/filters/delete/${filterId}`;
                                const data = {
                                    csrf_token: $('#csrf_token').val()
                                };
                                post_request_api(url, JSON.stringify(data))
                                    .then((data) => {
                                        if (notify_auto_api(data)) {
                                            fetchSavedFilters();
                                        }
                                    });
                        });
                    });
                }).on('hide.bs.select', function () {
                    $('.trash-wrapper').addClass('hidden-trash');
                });

                $('#savedFilters').on('change', function() {

                    const selectedFilterId = $('#savedFilters').val();
                    if (!selectedFilterId) return;

                    const url = `/filters/${selectedFilterId}`;

                    get_request_api(url)
                        .then((data) => {
                            if(!notify_auto_api(data, true)) return;
                            const queryParams = new URLSearchParams();
                            Object.entries(data.data.filter_data).forEach(([key, value]) => {
                                if (value !== '') {
                                    queryParams.set(key, value);
                                }
                            });

                            queryParams.set('filter_id', selectedFilterId);

                            // Update the URL and reload the page with the new filter settings
                            window.location.href = window.location.pathname + case_param() + '&' + queryParams.toString();
                        })
                });
            }
        });
}

$('#saveFilters').on('click', function () {
    $('#saveFilterModal').modal('show');
});

$('#saveFilterButton').on('click', function () {
    const filterData = $('#alertFilterForm').serializeArray().reduce((obj, item) => {
        obj[item.name] = item.value;
        return obj;
    }, {});

    const filterName = $('#filterName').val();
    const filterDescription = $('#filterDescription').val();
    const filterIsPrivate = $('#filterIsPrivate').prop('checked');

    filterData.custom_conditions = editor.getValue();

    if (!filterName) return;

    const url = '/filters/add';
    post_request_api(url, JSON.stringify({
        filter_name: filterName,
        filter_description: filterDescription,
        filter_data: filterData,
        filter_is_private: filterIsPrivate,
        filter_type: 'alerts',
        csrf_token: $('#csrf_token').val()
    }))
        .then(function (data) {
            if (notify_auto_api(data)) {
                fetchSavedFilters();
            }
        });

    $('#saveFilterModal').modal('hide');
});

function changeStatusAlert(alert_id, status_name) {
    let status_id = getAlertStatusId(status_name);

    let data = {
        'alert_status_id': status_id
    }
    updateAlert(alert_id, data, true);
}

async function changeAlertOwner(alertId) {
  // Fetch the user list from the endpoint
  const usersReq = await get_request_api('/manage/users/restricted/list');

  if (!notify_auto_api(usersReq, true)) { return; };

  users = usersReq.data;

  // Populate the select element with the fetched user list
  const userSelect = $('#changeOwnerAlertSelect');
  userSelect.empty();
  users.forEach((user) => {
    userSelect.append(`<option value="${user.user_id}">${user.user_name}</option>`);
  });

  $('#alertIDAssignModal').text(alertId);

  // Show the modal
  $('#changeAlertOwnerModal').modal('show');

  // Set up the form submission
  document.getElementById('assign-owner-button').onclick = async () => {
      // Get the selected user ID
      const newOwnerId = userSelect.val();

      // Send a POST request to the update endpoint
      updateAlert(alertId, {alert_owner_id: newOwnerId}, true)
      .then(() => {
            // Закрыть the modal
            $('#changeAlertOwnerModal').modal('hide');
      });
  };
}


async function changeBatchAlertOwner(alertId) {

    const selectedAlerts = getBatchAlerts();
    if (selectedAlerts.length === 0) {
        notify_error(t('Please select at least one alert to perform this action on.'));
        return;
    }

      // Fetch the user list from the endpoint
      const usersReq = await get_request_api('/manage/users/restricted/list');

      if (!notify_auto_api(usersReq, true)) { return; };

      users = usersReq.data;

      // Populate the select element with the fetched user list
      const userSelect = $('#changeOwnerAlertSelect');
      userSelect.empty();
      users.forEach((user) => {
        userSelect.append(`<option value="${user.user_id}">${user.user_name}</option>`);
      });

      $('#alertIDAssignModal').text(alertId);

      // Show the modal
      $('#changeAlertOwnerModal').modal('show');

      // Set up the form submission
      document.getElementById('assign-owner-button').onclick = async () => {
          // Get the selected user ID
          const newOwnerId = userSelect.val();

          // Send a POST request to the update endpoint
          updateBatchAlerts({alert_owner_id: newOwnerId})
          .then(() => {
                // Закрыть the modal
                $('#changeAlertOwnerModal').modal('hide');
          });
      };
}


async function updateAlert(alert_id, data = {}, do_refresh = false, collapse_toggle = false) {
  data['csrf_token'] = $('#csrf_token').val();
  return post_request_api('/alerts/update/' + alert_id, JSON.stringify(data)).then(function (data) {
    if (notify_auto_api(data)) {
      if (do_refresh) {
        const expanded = $(`#additionalDetails-${alert_id}`).hasClass('show');
        return refreshAlert(alert_id, data.data, expanded)
            .then(() => {
                const updatedAlertElement = $(`#alertCard-${alert_id}`);
                if (updatedAlertElement.length) {
                    updatedAlertElement.addClass('fade-it');
                }
            });
      }
    }
  });
}



function setFormValuesFromUrl() {
  const queryParams = new URLSearchParams(window.location.search);
  const form = $('#alertFilterForm');
  const ajaxCalls = [];

  queryParams.forEach((value, key) => {
    const input = form.find(`[name="${key}"]`);
   if (key === 'custom_conditions') {
        // If there's a custom_conditions param, load it into the ACE editor
        editor.setValue(value, 1); // 1 = move cursor to start
        return;
    }

    if (input.length > 0) {
      if (input.prop('type') === 'checkbox') {
        input.prop('checked', value in ['true', 'y', 'yes', '1', 'on']);
      } else if (input.is('select') && selectsConfig[input.attr('id')]) {
        const ajaxCall = new Promise((resolve, reject) => {
          input.one('click', function () {
            fetchSelectOptions(input.attr('id'), selectsConfig[input.attr('id')]).then(() => {
              input.val(value);
              resolve();
            }).catch(error => {
              console.error(error);
              reject(error);
            });
          }).trigger('click');
        });
        ajaxCalls.push(ajaxCall);
      } else {
        input.val(value);
      }
    }
    if (key === 'filter_id') {
        $('#savedFilters').selectpicker('val', value);
        $('.preset-dropdown-container').show();
    }
  });

  Promise.all(ajaxCalls)
    .then(() => {
      form.trigger('submit');
    })
    .catch(error => {
      console.error(t('Error setting form values:'), error);
    });
}


function fetchSelectOptions(selectElementId, configItem) {
  return new Promise((resolve, reject) => {
    get_request_api(configItem.url)
      .then(function (data) {
        if (!notify_auto_api(data, true)) {
          reject(t('Failed to fetch options'));
          return;
        }
        const selectElement = $(`#${selectElementId}`);
        selectElement.empty();
        selectElement.append($('<option>', {
          value: null,
          text: ''
        }));
        if (selectElementId === 'alert_owner_id') {
            selectElement.append($('<option>', {
                value: '-1',
                text: t('Unassigned')
            }));
        }

        data.data.forEach(function (item) {
          selectElement.append($('<option>', {
            value: item[configItem.id],
            text: item[configItem.name]
          }));
        });
        resolve();
      });
  });
}

function getBatchAlerts() {
    const selectedAlerts = [];
    $('.tickbox input[type="checkbox"]').each(function() {
        if ($(this).is(':checked')) {
          const alertId = $(this).data('alert-id');
          selectedAlerts.push(alertId);
        }
    });
    return selectedAlerts;
}

function changeStatusBatchAlerts(status_name) {
    const data = {
        'alert_status_id': getAlertStatusId(status_name)
    }

    updateBatchAlerts(data);
}

async function updateBatchAlerts(data_content= {}) {
    const selectedAlerts = getBatchAlerts();
    if (selectedAlerts.length === 0) {
        notify_error(t('Please select at least one alert to perform this action on.'));
        return;
    }

    const data = {
        'alert_ids': selectedAlerts,
        'csrf_token': $('#csrf_token').val(),
        'updates': data_content
    };

       window.swal({
          title: t('Alerts are being updated, please wait'),
          text: t("This window will close automatically when it's done"),
          icon: "/static/assets/img/loader.gif",
          button: false,
          allowOutsideClick: false
        });

    return post_request_api('/alerts/batch/update', JSON.stringify(data)).then(function (data) {
        if (notify_auto_api(data)) {
            setFormValuesFromUrl();
        }
    }).always(() => {
        window.swal.close();
    });

}


async function deleteBatchAlerts(data_content= {}) {
    const selectedAlerts = getBatchAlerts();
    if (selectedAlerts.length === 0) {
        notify_error(t('Please select at least one alert to perform this action on.'));
        return;
    }

    do_deletion_prompt(t('You are about to delete {count} alerts', { count: selectedAlerts.length }), true)
    .then((doDelete) => {
       window.swal({
              title: t('Alerts are being deleted, please wait'),
              text: t("This window will close automatically when it's done"),
              icon: "/static/assets/img/loader.gif",
              button: false,
              allowOutsideClick: false
        });
        if (doDelete) {
            const data = {
                'alert_ids': selectedAlerts,
                'csrf_token': $('#csrf_token').val()
            }

            return post_request_api('/alerts/batch/delete', JSON.stringify(data)).then(
                (data) => {
                    if (notify_auto_api(data)) {
                        setFormValuesFromUrl();
                    }
                }).always(() => {
                window.swal.close();
            });
        }
    });
}

let alertCount = 0;

function updateAlertBadge() {
    const badge = $('#refreshAlertsBadge');

    if (alertCount > 0) {
        badge.text(alertCount).show();
    } else {
        badge.hide();
    }
}

function refreshAlertRelationships(alertId) {
    // Get the checked status of each checkbox
    let fetch_open_alerts = $(`input[name="open_alerts_${alertId}"]`).prop('checked');
    let fetch_closed_alerts = $(`input[name="closed_alerts_${alertId}"]`).prop('checked');
    let fetch_open_cases = $(`input[name="open_cases_${alertId}"]`).prop('checked');
    let fetch_closed_cases = $(`input[name="closed_cases_${alertId}"]`).prop('checked');

    fetchSimilarAlerts(alertId, true, fetch_open_alerts, fetch_closed_alerts,
        fetch_open_cases, fetch_closed_cases);
}

$(document).ready(function () {
    for (const [selectElementId, configItem] of Object.entries(selectsConfig)) {
        $(`#${selectElementId}`).one('click', function () {
          fetchSelectOptions(selectElementId, configItem)
            .catch(error => console.error(error));
        });
      }


    editor = ace.edit('custom_conditions');
    if ($("#custom_conditions").attr("data-theme") != "dark") {
        editor.setTheme("ace/theme/tomorrow");
    } else {
        editor.setTheme("ace/theme/iris_night");
    }
    editor.session.setMode("ace/mode/json");
    editor.renderer.setShowGutter(true);
    editor.setOption("showLineNumbers", true);
    editor.setOption("showPrintMargin", false);
    editor.setOption("displayIndentGuides", true);
    editor.setOption("maxLines", "Infinity");
    editor.setOption("minLines", "2");
    editor.setOption("autoScrollEditorIntoView", true);
    editor.session.setUseWrapMode(true);
    editor.setOption("indentedSoftWrap", false);
    editor.renderer.setScrollMargin(8, 5)
    editor.setOption("enableBasicAutocompletion", true);

    editor.setOption("enableBasicAutocompletion", true);
    editor.setOption("enableLiveAutocompletion", true);

        // Use the langTools from ACE for autocompletion
        let langTools = ace.require("ace/ext/language_tools");

        // Define a custom completer
        let customCompleter = {
            getCompletions: function(editor, session, pos, prefix, callback) {
                const completions = [
                    { caption: '"field": "alert_title"', value: '"field": "alert_title"', meta: "field" },
                    { caption: '"field": "alert_description"', value: '"field": "alert_description"', meta: "field" },
                    { caption: '"field": "alert_source"', value: '"field": "alert_source"', meta: "field" },
                    { caption: '"field": "alert_tags"', value: '"field": "alert_tags"', meta: "field" },
                    { caption: '"field": "alert_status_id"', value: '"field": "alert_status_id"', meta: "field" },
                    { caption: '"field": "alert_severity_id"', value: '"field": "alert_severity_id"', meta: "field" },
                    { caption: '"field": "alert_classification_id"', value: '"field": "alert_classification_id"', meta: "field" },
                    { caption: '"field": "alert_customer_id"', value: '"field": "alert_customer_id"', meta: "field" },
                    { caption: '"field": "source_start_date"', value: '"field": "source_start_date"', meta: "field" },
                    { caption: '"field": "source_end_date"', value: '"field": "source_end_date"', meta: "field" },
                    { caption: '"field": "creation_start_date"', value: '"field": "creation_start_date"', meta: "field" },
                    { caption: '"field": "creation_end_date"', value: '"field": "creation_end_date"', meta: "field" },
                    { caption: '"field": "alert_assets"', value: '"field": "alert_assets"', meta: "field" },
                    { caption: '"field": "alert_iocs"', value: '"field": "alert_iocs"', meta: "field" },
                    { caption: '"field": "alert_ids"', value: '"field": "alert_ids"', meta: "field" },
                    { caption: '"field": "source_reference"', value: '"field": "source_reference"', meta: "field" },
                    { caption: '"field": "case_id"', value: '"field": "case_id"', meta: "field" },
                    { caption: '"field": "alert_owner_id"', value: '"field": "alert_owner_id"', meta: "field" },
                    { caption: '"field": "alert_resolution_id"', value: '"field": "alert_resolution_id"', meta: "field" },
                    { caption: '"operator": "in"', value: '"operator": "in"', meta: "operator" },
                    { caption: '"operator": "not_in"', value: '"operator": "not_in"', meta: "operator" },
                    { caption: '"operator": "eq"', value: '"operator": "eq"', meta: "operator" },
                    { caption: '"operator": "like"', value: '"operator": "like"', meta: "operator" },
                    { caption: '"value": [1]', value: '"value": [1]', meta: "value" }
                ];

                // Filter the completions based on the current prefix if desired
                let filtered = completions;
                if (prefix) {
                    filtered = completions.filter(item => item.caption.toLowerCase().includes(prefix.toLowerCase()));
                }

                callback(null, filtered);
            }
        };

        // Add the custom completer to ACE
        langTools.addCompleter(customCompleter);

    fetchSavedFilters()
        .then(() => {
            setFormValuesFromUrl();
        });
    getAlertStatusList();
    getAlertResolutionList();

    // Connect to socket.io alerts namespace
    const socket = io.connect('/alerts');

  $('#toggle-selection-mode').on('click', function() {
    // Toggle the 'selection-mode' class on the body element
    $('body').toggleClass('selection-mode');

    // Check if the selection mode is active
    const selectionModeActive = $('body').hasClass('selection-mode');

    // Update the button text
    $(this).text(selectionModeActive ? t('Cancel') : t('Select'));

    // Toggle the display of avatars, tickboxes and selection-related buttons
    $('.alert-card-selectable').each(function() {
      const avatarTickboxWrapper = $(this).find('.avatar-tickbox-wrapper');
      avatarTickboxWrapper.find('.avatar-wrapper').toggle(!selectionModeActive);
      avatarTickboxWrapper.find('.tickbox').toggle(selectionModeActive);
    });

    $('#select-deselect-all').toggle(selectionModeActive).text(t('Select all'));
    $('#alerts-batch-actions').toggle(selectionModeActive);
  });

  $('#select-deselect-all').on('click', function() {
    const allSelected = $('.tickbox input[type="checkbox"]:not(:checked)').length === 0;

    $('.tickbox input[type="checkbox"]').prop('checked', !allSelected);
    $(this).text(allSelected ? t('Select all') : t('Deselect all'));
  });

  $(document).on('click', '.enricher-option', function (event) {
    event.preventDefault();
    const enricher = $(this).data('enricher');
    if (enricher !== 'ioc') {
        return;
    }

    const alertId = $(this).data('alert-id');
    if (alertId) {
        enrichAlertsIocs([alertId]);
        return;
    }

    const selectedAlerts = getBatchAlerts();
    enrichAlertsIocs(selectedAlerts);
  });

    socket.on('new_alert', function (data) {
        const badge = $('#newAlertsBadge');
        const currentCount = parseInt(badge.text()) || 0;
        badge.text(currentCount + 1).show();
        badge.attr('title', t('New alerts available'));
    });

});
