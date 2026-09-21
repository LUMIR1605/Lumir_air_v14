"""Subprocess-only bridge for an externally installed Holehe package.

This module deliberately avoids Holehe's CLI entry point because version 1.61
performs an update check and launches all modules without LUMIR's budget.
"""

import argparse
import importlib
import importlib.metadata
import json
from pathlib import Path
import pkgutil
import shutil
import sys

# When this file is executed directly, its directory contains our adapter
# named holehe.py. Remove that directory from sys.path so imports resolve
# to the externally installed Holehe package instead of the local adapter.
_WORKER_DIR = Path(__file__).resolve().parent
sys.path[:] = [
    entry for entry in sys.path
    if Path(entry or ".").resolve() != _WORKER_DIR
]


_LOGIN = frozenset({
    "amazon", "bitmoji", "ebay", "eventbrite", "evernote", "flickr", "freelancer",
    "hubspot", "insightly", "lastfm", "nutshell", "patreon", "pipedrive", "snapchat",
    "wordpress", "yahoo", "zoho",
})
_FORGOT = frozenset({"adobe", "mail_ru", "odnoklassniki", "samsung"})
_OTHER = frozenset({"gravatar", "office365", "protonmail"})


def _modules() -> list[tuple[str, object]]:
    package = importlib.import_module("holehe.modules")
    values: list[tuple[str, object]] = []
    for item in pkgutil.walk_packages(package.__path__, prefix="holehe.modules."):
        if item.ispkg:
            continue
        service_id = item.name.rsplit(".", 1)[-1]
        try:
            module = importlib.import_module(item.name)
            function = getattr(module, service_id, None)
        except Exception:
            continue
        if callable(function):
            values.append((service_id, function))
    return sorted(values, key=lambda value: value[0])


def _method(service_id: str) -> str:
    if service_id in _LOGIN:
        return "login"
    if service_id in _FORGOT:
        return "forgot-password"
    if service_id in _OTHER:
        return "other"
    return "register"


def _diagnose() -> int:
    try:
        version = importlib.metadata.version("holehe")
        modules = _modules()
        available = True
        reason = "Holehe library and provider modules are importable"
    except Exception as error:
        version = None
        modules = []
        available = False
        reason = f"{type(error).__name__}: Holehe library is unavailable"
    print(json.dumps({
        "library_available": available,
        "cli_available": (
            shutil.which("holehe") is not None
            or Path(sys.executable).with_name("holehe.exe").is_file()
        ),
        "version": version,
        "provider_modules_detected": len(modules),
        "python_interpreter": sys.executable,
        "python_version": ".".join(str(item) for item in sys.version_info[:3]),
        "reason": reason,
    }, sort_keys=True))
    return 0 if available else 2


def _run() -> int:
    request = json.loads(sys.stdin.readline())
    email = request["email"]
    budget = request["budget"]
    max_services = int(budget["max_services"])
    concurrency = int(budget["max_concurrency"])
    timeout = float(budget["per_service_timeout_seconds"])
    version = importlib.metadata.version("holehe")
    modules = _modules()[:max_services]
    import httpx
    import trio

    async def execute() -> None:
        limiter = trio.CapacityLimiter(concurrency)
        client = httpx.AsyncClient(timeout=timeout)

        async def one(service_id: str, function: object) -> None:
            raw: list[dict[str, object]] = []
            async with limiter:
                try:
                    with trio.move_on_after(timeout) as scope:
                        await function(email, client, raw)
                    if scope.cancelled_caught:
                        raw = [{"name": service_id, "domain": service_id, "exists": None,
                                "rateLimit": False, "error": True, "error_code": "TIMEOUT"}]
                except Exception as error:
                    raw = [{"name": service_id, "domain": service_id, "exists": None,
                            "rateLimit": False, "error": True,
                            "error_code": f"PROVIDER_{type(error).__name__.upper()}"}]
            payload = dict(raw[-1]) if raw else {
                "name": service_id, "domain": service_id, "exists": None,
                "rateLimit": False, "error": False, "error_code": "EMPTY_RESPONSE",
            }
            payload.setdefault("name", service_id)
            payload.setdefault("domain", service_id)
            payload["detection_method"] = _method(service_id)
            payload["module_version"] = version
            print(json.dumps({"event": "result", "payload": payload}, ensure_ascii=False), flush=True)

        async with trio.open_nursery() as nursery:
            for service_id, function in modules:
                nursery.start_soon(one, service_id, function)
        await client.aclose()

    trio.run(execute)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--diagnose", action="store_true")
    args = parser.parse_args()
    if args.diagnose:
        return _diagnose()
    try:
        return _run()
    except Exception as error:
        print(json.dumps({"event": "worker_error", "error_code": type(error).__name__}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

