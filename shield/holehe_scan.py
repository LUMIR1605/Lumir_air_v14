"""Adapter for the locally installed Holehe command-line tool."""

import re
import subprocess


TIMEOUT_SECONDS = 120
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _result(status, *, checked=0, services=None, error_reason=None, exit_code=None):
    return {
        "module": "holehe",
        "scan_status": status,
        "checked": checked,
        "services": services or [],
        "risk": "unknown",
        "score": None,
        "error_reason": error_reason,
        "process_exit_code": exit_code,
    }


def _service_names(stdout):
    services = []
    seen = set()
    checked = 0
    for line in stdout.splitlines():
        clean_line = _ANSI_ESCAPE.sub("", line).strip()
        if not clean_line.startswith("[+]"):
            continue
        checked += 1
        name = " ".join(clean_line[3:].split())
        if not name or "email used" in name.casefold():
            continue
        identifier = name.casefold()
        if identifier not in seen:
            seen.add(identifier)
            services.append(name)
    return checked, services


def scan(email):
    """Return normalized probable service names without exposing CLI output."""
    command = ["holehe", "--only-used", "--no-color", email]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return _result("unavailable", error_reason="HOLEHE_NOT_INSTALLED")
    except subprocess.TimeoutExpired:
        return _result("timeout", error_reason="HOLEHE_TIMEOUT")
    except subprocess.CalledProcessError:
        return _result("error", error_reason="HOLEHE_PROCESS_FAILED")
    except OSError:
        return _result("error", error_reason="HOLEHE_PROCESS_ERROR")

    exit_code = getattr(result, "returncode", 0)
    if exit_code != 0:
        return _result("error", error_reason="HOLEHE_PROCESS_FAILED", exit_code=exit_code)

    checked, services = _service_names(getattr(result, "stdout", "") or "")
    return _result("completed", checked=checked, services=services, exit_code=exit_code)
