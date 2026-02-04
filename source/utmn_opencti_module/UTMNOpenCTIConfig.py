module_name = "UTMN_OpenCTI_module"
module_description = "Обогащает IoCs с помощью OpenCTI"
interface_version = "1.2.0"
module_version = "0.1.0"
pipeline_support = False
pipeline_info = {}

module_configuration = [
    {
        "param_name": "opencti_url",
        "param_human_name": "OpenCTI URL",
        "param_description": "Base URL of OpenCTI (without /graphql)",
        "default": "",
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "opencti_token",
        "param_human_name": "OpenCTI API token",
        "param_description": "Токен, используемый для аутентификации в OpenCTI",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "opencti_verify_tls",
        "param_human_name": "Verify TLS",
        "param_description": "Проверка TLS-сертификатов для запросов OpenCTI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Connection"
    },
    {
        "param_name": "opencti_timeout",
        "param_human_name": "Request timeout (s)",
        "param_description": "Таймаут HTTP для запросов OpenCTI в секундах",
        "default": 120,
        "mandatory": True,
        "type": "int",
        "section": "Connection"
    },
    {
        "param_name": "opencti_use_proxy",
        "param_human_name": "Use server proxy",
        "param_description": "Используйте настройки прокси-сервера IRIS для запросов OpenCTI.",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Connection"
    },
    {
        "param_name": "opencti_max_results",
        "param_human_name": "Max results per query",
        "param_description": "Максимальное количество объектов OpenCTI, возвращаемых на один IOC",
        "default": 15,
        "mandatory": True,
        "type": "int",
        "section": "Search"
    },
    {
        "param_name": "opencti_max_iocs_per_alert",
        "param_human_name": "Max IOCs per alert",
        "param_description": "Лимит обогощённых IOC для каждого оповещения.",
        "default": 100,
        "mandatory": True,
        "type": "int",
        "section": "Search"
    },
    {
        "param_name": "opencti_ioc_type_allowlist",
        "param_human_name": "IOC type allowlist",
        "param_description": "Разделенные запятыми типы для уточнения данных (ip, domain, url, hash, email, hostname, all)",
        "default": "ip,domain,url,hash,email,hostname",
        "mandatory": True,
        "type": "string",
        "section": "Search"
    },
    {
        "param_name": "opencti_observable_search_enabled",
        "param_human_name": "Search observables",
        "param_description": "Запрос наблюдаемых объектов OpenCTI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Search"
    },
    {
        "param_name": "opencti_indicator_search_enabled",
        "param_human_name": "Search indicators",
        "param_description": "Запрос индикаторов OpenCTI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Search"
    },
    {
        "param_name": "opencti_rich_query_enabled",
        "param_human_name": "Rich query fields",

        "param_description": "Использовать дополнительное обогощение OpenCTI",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Search"
    },
    {
        "param_name": "opencti_relations_enabled",
        "param_human_name": "Fetch relations",
        "param_description": "Получение связей для соответствующих сущностей",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Search"
    },
    {
        "param_name": "opencti_relations_entities_max",
        "param_human_name": "Max entities for relations",
        "param_description": "Максимальное количество совпадающих сущностей, используемых для получения связей.",
        "default": 5,
        "mandatory": True,
        "type": "int",
        "section": "Search"
    },
    {
        "param_name": "opencti_relations_max",
        "param_human_name": "Max relations per entity",
        "param_description": "Максимальное количество связей, извлекаемых для одной сущности.",
        "default": 20,
        "mandatory": True,
        "type": "int",
        "section": "Search"
    },
    {
        "param_name": "opencti_store_raw_response",
        "param_human_name": "Store raw response",
        "param_description": "Показывать сырые ответы OpenCTI в обогащении IOC.",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Storage"
    },
    {
        "param_name": "opencti_on_alert_create_enabled",
        "param_human_name": "Trigger on alert create",
        "param_description": "Автоматическое обогощение alert, при его создании",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "opencti_on_alert_update_enabled",
        "param_human_name": "Trigger on alert update",
        "param_description": "Обогощение alert, только при нажатии на кнопку",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "opencti_run_async_hooks",
        "param_human_name": "Run hooks asynchronously",
        "param_description": "Асинхронный запуск задач (Экспериментальная функция)",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "opencti_manual_hook_enabled",
        "param_human_name": "Manual trigger on alerts",
        "param_description": "Включение ручного обогощения",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "opencti_manual_ioc_hook_enabled",
        "param_human_name": "Manual trigger on IOCs",
        "param_description": "Включение ручного обогощения, для отдельных IoC",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    }
]
