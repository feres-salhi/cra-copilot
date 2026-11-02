"""Q1: show one Windows toast notification with Windows PowerShell's built-in notification API (no new package).

SECURITY (read this before changing anything):
  - The PowerShell script below is ONE FIXED TEXT. It is never built from any value. The title and body travel as
    ENVIRONMENT VARIABLES of the child process, i.e. as data. PowerShell never parses them as code.
  - Before anything is started, title and body must match a strict pattern (letters, digits, blank and . , : ; ( ) / -).
    The script checks the same pattern again, and puts the text into the notification with CreateTextNode (which
    escapes it), not into XML text.
  - The program is started by its FULL path (SystemRoot, System32, WindowsPowerShell, v1.0, powershell.exe), as a
    list of arguments, without a shell. So no file in the current folder can be run instead, and no quoting can go wrong.
  - The child gets only a short list of environment variables (no keys, no secrets).
  - Known limit: exit code 0 only means Windows accepted the toast. If Focus Assist / Do Not Disturb is on, or
    notifications for "Windows PowerShell" are switched off in Windows settings, nothing is seen. That is why every
    alert is ALSO written to cache/alerts.log.
  - Any failure gives False. The caller then writes the alert to the log instead. This function never raises.
"""

import base64
import os
import re
import subprocess  # nosec B404 - the only place; fixed script, full path, list arguments, no shell (see the notes above and tests/test_toast.py)
import sys
from pathlib import Path

from src import alerts

TIMEOUT_SECONDS = 20
PASSED_VARIABLES = ("SystemRoot", "windir", "SystemDrive", "PATH", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "ProgramData")
WINDOWS_FOLDER = re.compile(r"[A-Za-z]:\\[^\\/:*?\"<>|]+(\\[^\\/:*?\"<>|]+)*")  # a drive letter path, never a network share

# The AppUserModelId of Windows PowerShell itself: Windows shows toasts for it without any registration.
SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$t = $env:CRA_TOAST_TITLE
$b = $env:CRA_TOAST_BODY
$ok = '\A[A-Za-z0-9 .,:;()/-]{1,300}\z'
if ([string]::IsNullOrEmpty($t) -or [string]::IsNullOrEmpty($b)) { exit 3 }
if (($t -cnotmatch $ok) -or ($b -cnotmatch $ok)) { exit 4 }
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$n = $x.GetElementsByTagName('text')
[void]$n.Item(0).AppendChild($x.CreateTextNode($t))
[void]$n.Item(1).AppendChild($x.CreateTextNode($b))
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))
"""


def _powershell_path(environ):
    root = environ.get("SystemRoot")
    if not root or not WINDOWS_FOLDER.fullmatch(root):
        return None
    path = Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return path if path.is_file() else None


def show(title, body, runner=None, platform=None):
    """True if Windows PowerShell reported success, otherwise False. Never raises. `runner` and `platform` are for tests."""
    try:
        platform = sys.platform if platform is None else platform
        if platform != "win32":
            return False
        if not isinstance(title, str) or not isinstance(body, str):
            return False
        if not alerts.SAFE_TEXT.fullmatch(title) or not alerts.SAFE_TEXT.fullmatch(body):
            return False
        if runner is None:
            if "PYTEST_CURRENT_TEST" in os.environ:  # a test must never start the real PowerShell
                return False
            runner = subprocess.run
        exe = _powershell_path(os.environ)
        if exe is None:
            return False
        encoded = base64.b64encode(SCRIPT.encode("utf-16-le")).decode("ascii")
        env = {name: os.environ[name] for name in PASSED_VARIABLES if name in os.environ}
        env["CRA_TOAST_TITLE"] = title
        env["CRA_TOAST_BODY"] = body
        result = runner([str(exe), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
                        env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT_SECONDS, shell=False, check=False,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.returncode == 0
    except Exception:
        return False
