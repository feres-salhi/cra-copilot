"""A tiny reader for a `.env` file (no extra package).

It only READS lines like  NAME=value  at the moment a setting is needed. It never prints a value, never changes the
process environment, and ignores everything it does not understand. Keys live only in `.env` (CLAUDE.md trust rule 4).
"""

import hmac
import re
from pathlib import Path

MAX_ENV_BYTES = 64 * 1024
MAX_VALUE_LENGTH = 512

_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_API_KEY = re.compile(r"[A-Za-z0-9_.-]{20,200}")  # a dot is allowed: newer Google keys may contain one
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_PLACEHOLDER_KEYS = {"put-your-key-here"}  # the sample value in .env.example is not a key


class Secret:
    """A box around a secret (an API key). Printing, repr, f-strings, logging, pickling and copying never show the
    value: they give "***". The real text comes out only through `reveal()`, which is called at the one moment the
    request header is set. A plain string in a function argument shows up in tracebacks; this box does not.
    """

    __slots__ = ("_value",)

    def __init__(self, value):
        if not isinstance(value, str):
            raise TypeError("a Secret holds text")
        object.__setattr__(self, "_value", value)

    def reveal(self):
        return self._value

    def __setattr__(self, name, value):
        raise AttributeError("a Secret cannot be changed")

    def __repr__(self):
        return "***"

    __str__ = __repr__

    def __format__(self, spec):
        return "***"

    def __eq__(self, other):  # equal only to another Secret with the same value; never to a plain string
        return isinstance(other, Secret) and hmac.compare_digest(self._value.encode(), other._value.encode())

    __hash__ = object.__hash__  # by identity: a hash of the value would be a stable fingerprint of the key

    def __reduce__(self):
        raise TypeError("a Secret cannot be pickled or copied")


def load_env_file(path):
    """{NAME: value} from the file, or {} if it is missing, too big, unreadable or not UTF-8."""
    try:
        path = Path(path)
        if not path.is_file():
            return {}
        with open(path, "rb") as handle:
            raw = handle.read(MAX_ENV_BYTES + 1)
        if len(raw) > MAX_ENV_BYTES:
            return {}
        text = raw.decode("utf-8-sig")
    except (OSError, ValueError):
        return {}
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not _NAME.fullmatch(name) or len(value) > MAX_VALUE_LENGTH or (value and not value.isprintable()):
            continue
        values[name] = value
    return values


def get_setting(name, file_values, environ, default=None):
    """A real environment variable wins over the file. A blank value counts as not set."""
    for source in (environ, file_values):
        value = source.get(name) if source else None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def get_secret(name, file_values, environ):
    """Like get_setting, but the answer comes back already boxed as a Secret (or None)."""
    value = get_setting(name, file_values, environ)
    return None if value is None else Secret(value)


def valid_api_key(key):
    """True only for a Secret that holds something that looks like a key and cannot carry a line break or space
    into a header. A plain string is NOT accepted: keys travel boxed."""
    if not isinstance(key, Secret):
        return False
    text = key.reveal()
    return text not in _PLACEHOLDER_KEYS and _API_KEY.fullmatch(text) is not None


def valid_model_name(model):
    """True only for a plain model name: it ends up inside a web address, so no slash, colon, question mark or space."""
    return isinstance(model, str) and _MODEL.fullmatch(model) is not None and ".." not in model
