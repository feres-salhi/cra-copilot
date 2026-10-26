"""A tiny reader for a `.env` file (no extra package).

It only READS lines like  NAME=value  at the moment a setting is needed. It never prints a value, never changes the
process environment, and ignores everything it does not understand. Keys live only in `.env` (CLAUDE.md trust rule 4).
"""

import re
from pathlib import Path

MAX_ENV_BYTES = 64 * 1024
MAX_VALUE_LENGTH = 512

_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_API_KEY = re.compile(r"[A-Za-z0-9_.-]{20,200}")  # a dot is allowed: newer Google keys may contain one
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_PLACEHOLDER_KEYS = {"put-your-key-here"}  # the sample value in .env.example is not a key


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


def valid_api_key(key):
    """True only for something that looks like a key and cannot carry a line break or space into a header."""
    return isinstance(key, str) and key not in _PLACEHOLDER_KEYS and _API_KEY.fullmatch(key) is not None


def valid_model_name(model):
    """True only for a plain model name: it ends up inside a web address, so no slash, colon, question mark or space."""
    return isinstance(model, str) and _MODEL.fullmatch(model) is not None and ".." not in model
