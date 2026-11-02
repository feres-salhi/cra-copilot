"""How to print a command the tool suggests, in the form that really works on THIS computer.

The tool used to print "cra draft ..." although on many computers there is no program called `cra`; the working form
is "python -m src draft ...". This file works the form out from how the tool was started. It installs nothing.
"""

import os
import re
import sys

_SAFE_PATH = re.compile(r"[A-Za-z0-9_.:\\/ -]+")  # anything else (quotes, $, `, ;, &, (, ) ...) is never put into a command
_override = None  # tests only: a fixed text that replaces the derived one


def set_override(text):
    """Tests only. None switches the fixed text off again."""
    global _override
    _override = text


def _stem(path):
    name = os.path.basename(str(path)).lower()
    return name[:-4] if name.endswith(".exe") else name


def command_prefix(executable=None, argv0=None, cwd=None):
    """The start of every suggested command: "cra" if the tool was started through a real `cra` program, otherwise
    the Python that is running now followed by "-m src" (a relative path if Python lives inside the current folder).
    Written for PowerShell, and it works from the folder the tool was started in. If the Python path holds special
    characters, the plain "python -m src" is shown instead."""
    if _override is not None:
        return _override
    executable = sys.executable if executable is None else executable
    argv0 = (sys.argv[0] if sys.argv else "") if argv0 is None else argv0
    cwd = os.getcwd() if cwd is None else cwd
    if _stem(argv0) == "cra":
        return "cra"
    if not executable:
        return "python -m src"
    path = executable[:-4] if executable.lower().endswith(".exe") else executable
    try:
        inside = os.path.commonpath([os.path.abspath(executable), os.path.abspath(cwd)]) == os.path.abspath(cwd)
    except ValueError:  # another drive
        inside = False
    if inside:
        path = os.path.relpath(path, cwd)
        if os.sep not in path:
            path = os.curdir + os.sep + path  # PowerShell would otherwise look the name up on the PATH
    if not _SAFE_PATH.fullmatch(path):
        return "python -m src"  # a path with special characters is never pasted into a command
    if " " in path:
        return f"& '{path}' -m src"  # PowerShell: & runs a quoted program path; single quotes expand nothing
    return f"{path} -m src"


def command(*words):
    """A finished command text, for example command("approve", "case-0123456789ab")."""
    return " ".join([command_prefix(), *words])
