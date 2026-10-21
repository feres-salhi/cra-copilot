"""One shared helper so a file name from outside can never point outside its folder."""

import re
from pathlib import Path

SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
# Windows treats these names as devices (the file name before the first dot decides).
WINDOWS_DEVICE_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def safe_join(base, name):
    """Return base/name, or raise ValueError if `name` is not a plain, safe file name.

    Checks: only simple characters (no slashes, drive letters or `..`), and the resolved
    result must still be inside `base` (this also stops symlinks that point elsewhere).
    """
    if not isinstance(name, str) or not SAFE_NAME.fullmatch(name) or ".." in name or name.endswith("."):
        raise ValueError("unsafe file name")
    if name.split(".")[0].upper() in WINDOWS_DEVICE_NAMES:
        raise ValueError("unsafe file name (Windows device name)")
    base_path = Path(base).resolve()
    target = (base_path / name).resolve()
    if target.parent != base_path:
        raise ValueError("path leaves its folder")
    return base_path / name
