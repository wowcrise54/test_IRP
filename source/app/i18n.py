from flask_babel import get_domain
from flask_babel import gettext


# Keep explicit keys as a fallback for environments where catalog introspection
# is unavailable.
_FALLBACK_JS_KEYS = [
    "Operation succeeded",
    "Operation failed",
    "Permission denied",
    "We got error {status} - {statusText} requesting {url}",
]


def get_js_messages():
    messages = {}
    try:
        translations = get_domain().get_translations()
        catalog = getattr(translations, "_catalog", {})
        for msgid, msgstr in catalog.items():
            if isinstance(msgid, str) and isinstance(msgstr, str):
                messages[msgid] = msgstr
    except Exception:
        # Fallback below keeps JS translation functional.
        pass

    for key in _FALLBACK_JS_KEYS:
        messages.setdefault(key, gettext(key))

    return messages
