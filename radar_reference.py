#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         LUMIR AIR v13.0.1                                  ║
║               Intelligence Radar for Android / Termux / Python 3.13        ║
║                                                                              ║
║  Autor   : LUMIR Project                                                    ║
║  Wersja  : 13.0.1                                                           ║
║  Python  : 3.13+                                                            ║
║  Plik    : radar_lumir_air_v13.py                                           ║
║                                                                              ║
║  Źródła danych:                                                             ║
║    • GitHub API (REST v3)                                                   ║
║    • Hacker News (Algolia API)                                              ║
║    • Reddit (JSON API, no auth)                                             ║
║    • Hugging Face (Hub API)                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

Licencja: MIT
"""

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTY STANDARDOWEJ BIBLIOTEKI PYTHONA
# ─────────────────────────────────────────────────────────────────────────────
import os
import sys
import platform
import shutil
import socket
import json
import datetime
import textwrap
import time
import re
from pathlib import Path
from typing import Any, Optional

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTY ZEWNĘTRZNYCH BIBLIOTEK
# ─────────────────────────────────────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[BŁĄD] Brak biblioteki 'requests'. Zainstaluj: pip install requests")
    sys.exit(1)

try:
    import feedparser
except ImportError:
    print("[BŁĄD] Brak biblioteki 'feedparser'. Zainstaluj: pip install feedparser")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[BŁĄD] Brak biblioteki 'beautifulsoup4'. Zainstaluj: pip install beautifulsoup4")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich.rule import Rule
    from rich.style import Style
    from rich import box
except ImportError:
    print("[BŁĄD] Brak biblioteki 'rich'. Zainstaluj: pip install rich")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[BŁĄD] Brak biblioteki 'pyyaml'. Zainstaluj: pip install pyyaml")
    sys.exit(1)

try:
    from tabulate import tabulate
except ImportError:
    print("[BŁĄD] Brak biblioteki 'tabulate'. Zainstaluj: pip install tabulate")
    sys.exit(1)

try:
    import markdown
except ImportError:
    print("[BŁĄD] Brak biblioteki 'markdown'. Zainstaluj: pip install markdown")
    sys.exit(1)

# lxml jest używany przez BeautifulSoup jako parser — weryfikujemy dostępność
try:
    import lxml  # noqa: F401
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALNY KONSOL RICH (singleton)
# ─────────────────────────────────────────────────────────────────────────────
console = Console(highlight=True, markup=True)

# ─────────────────────────────────────────────────────────────────────────────
# KONFIGURACJA GLOBALNA
# ─────────────────────────────────────────────────────────────────────────────
CONFIG: dict[str, Any] = {
    # ── Katalogi ──────────────────────────────────────────────────────────────
    "project_root": Path.home() / "lumir_air_v13",
    "reports_dir":  Path.home() / "storage" / "downloads" / "LUMIR",

    # ── Wersja projektu ───────────────────────────────────────────────────────
    "version": "13.0.1",
    "app_name": "LUMIR AIR",

    # ── Sieć ─────────────────────────────────────────────────────────────────
    "timeout": 15,               # sekundy na żądanie HTTP
    "max_retries": 3,            # liczba ponowień przy błędzie
    "retry_backoff": 0.5,        # współczynnik cofnięcia wykładniczego

    # ── GitHub API ────────────────────────────────────────────────────────────
    # Ustaw zmienną środowiskową GITHUB_TOKEN, aby uniknąć limitu 60 req/h
    "github_api_base": "https://api.github.com",
    "github_search_query": "language:python stars:>1000",
    "github_search_limit": 10,

    # ── Hacker News ───────────────────────────────────────────────────────────
    "hn_api_url": "https://hn.algolia.com/api/v1/search",
    "hn_query": "AI python",
    "hn_limit": 10,

    # ── Reddit ────────────────────────────────────────────────────────────────
    "reddit_subreddits": ["python", "MachineLearning", "artificial"],
    "reddit_limit": 5,           # posty na subreddit

    # ── Hugging Face ──────────────────────────────────────────────────────────
    "hf_api_base": "https://huggingface.co/api",
    "hf_models_limit": 10,
    "hf_sort": "downloads",      # downloads | trending | likes | created_at

    # ── User-Agent ────────────────────────────────────────────────────────────
    "user_agent": "LUMIR-AIR/13.0.1 (Termux; Android; Python/3.13)",
}

# ─────────────────────────────────────────────────────────────────────────────
# STAŁE KOLORÓW I ETYKIET DLA RICH
# ─────────────────────────────────────────────────────────────────────────────
COLORS = {
    "header":   "bold cyan",
    "ok":       "bold green",
    "warn":     "bold yellow",
    "error":    "bold red",
    "info":     "dim white",
    "accent":   "bold magenta",
    "section":  "bold blue",
    "muted":    "grey50",
}

# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 1 — NARZĘDZIA POMOCNICZE
# ═════════════════════════════════════════════════════════════════════════════

def make_http_session() -> requests.Session:
    """
    Tworzy i zwraca obiekt :class:`requests.Session` ze skonfigurowanymi:
      - nagłówkiem User-Agent
      - strategią automatycznych ponowień (retry) przy błędach 429, 500, 502, 503, 504
      - limitem czasu (timeout jest przekazywany przy każdym wywołaniu .get())

    Centralny punkt tworzenia sesji — dzięki temu wszystkie żądania HTTP
    w programie współdzielą tę samą konfigurację transportu.
    """
    session = requests.Session()

    # Strategia ponowień: max 3 próby, backoff wykładniczy
    retry_strategy = Retry(
        total=CONFIG["max_retries"],
        backoff_factor=CONFIG["retry_backoff"],
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)

    # Domyślny nagłówek identyfikujący klienta
    session.headers.update({
        "User-Agent": CONFIG["user_agent"],
        "Accept":     "application/json",
    })

    return session


def safe_get(
    session: requests.Session,
    url: str,
    params: Optional[dict] = None,
    extra_headers: Optional[dict] = None,
    as_json: bool = True,
) -> Optional[Any]:
    """
    Bezpieczne wywołanie HTTP GET z obsługą wyjątków.

    Parametry
    ----------
    session       : aktywna sesja HTTP
    url           : docelowy adres URL
    params        : słownik query-string (opcjonalny)
    extra_headers : dodatkowe nagłówki HTTP (opcjonalne)
    as_json       : jeśli True, parsuje odpowiedź jako JSON; jeśli False,
                    zwraca surowy tekst

    Zwraca
    ------
    Sparsowane dane (dict/list) lub tekst, albo None w przypadku błędu.
    """
    try:
        headers = {}
        if extra_headers:
            headers.update(extra_headers)

        response = session.get(
            url,
            params=params,
            headers=headers,
            timeout=CONFIG["timeout"],
        )
        response.raise_for_status()

        if as_json:
            return response.json()
        return response.text

    except requests.exceptions.Timeout:
        console.print(f"[{COLORS['warn']}]⚠  Timeout: {url}[/]")
    except requests.exceptions.HTTPError as exc:
        console.print(f"[{COLORS['error']}]✗  HTTP {exc.response.status_code}: {url}[/]")
    except requests.exceptions.ConnectionError:
        console.print(f"[{COLORS['error']}]✗  Brak połączenia: {url}[/]")
    except json.JSONDecodeError:
        console.print(f"[{COLORS['warn']}]⚠  Nieprawidłowy JSON: {url}[/]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[{COLORS['error']}]✗  Nieznany błąd ({type(exc).__name__}): {url}[/]")

    return None


def truncate_text(text: str, max_len: int = 120) -> str:
    """
    Skraca tekst do zadanej długości, dodając wielokropek na końcu.
    Funkcja pomocnicza dla wyświetlania w tabelach.
    """
    if not text:
        return ""
    text = text.strip().replace("\n", " ")
    return textwrap.shorten(text, width=max_len, placeholder="…")


def format_number(n: int | float | None) -> str:
    """
    Formatuje liczbę do postaci czytelnej dla człowieka (np. 12 500).
    Zwraca '—' dla wartości None.
    """
    if n is None:
        return "—"
    return f"{int(n):,}".replace(",", " ")


def now_iso() -> str:
    """Zwraca aktualny czas UTC w formacie ISO 8601 z dokładnością do sekund."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def today_str() -> str:
    """Zwraca aktualną datę lokalną w formacie YYYY-MM-DD."""
    return datetime.datetime.now().strftime("%Y-%m-%d")


def slugify(text: str) -> str:
    """
    Zamienia tekst na bezpieczną nazwę pliku:
      - zamienia spacje i znaki specjalne na '_'
      - usuwa znaki niedozwolone w systemach plików
    """
    text = text.lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "_", text)
    return text.strip("_")


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 2 — WERYFIKACJA ŚRODOWISKA
# ═════════════════════════════════════════════════════════════════════════════

def check_environment() -> dict[str, Any]:
    """
    Sprawdza środowisko uruchomieniowe programu.

    Weryfikuje:
      - wersję Pythona (wymagana >= 3.10)
      - system operacyjny i architekturę CPU
      - obecność interpretera w Termux (/data/data/com.termux)
      - dostępność bibliotek zewnętrznych
      - dostępność komendy 'curl' i 'git' w systemie (via shutil.which)
      - dostępność i rozmiar wolnego miejsca w katalogu domowym

    Zwraca
    ------
    Słownik z wynikami wszystkich sprawdzeń.
    """
    results: dict[str, Any] = {}

    # ── Python ────────────────────────────────────────────────────────────────
    py_ver = sys.version_info
    results["python_version"] = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    results["python_ok"] = (py_ver.major == 3 and py_ver.minor >= 10)

    # ── System operacyjny ─────────────────────────────────────────────────────
    results["platform"] = platform.system()
    results["machine"]  = platform.machine()
    results["node"]     = platform.node()

    # ── Wykrywanie Termux ──────────────────────────────────────────────────────
    termux_prefix = os.environ.get("PREFIX", "")
    results["is_termux"] = "com.termux" in termux_prefix or \
                           "com.termux" in os.environ.get("HOME", "")

    # ── Narzędzia systemowe ───────────────────────────────────────────────────
    results["curl_available"] = shutil.which("curl") is not None
    results["git_available"]  = shutil.which("git")  is not None

    # ── Biblioteki zewnętrzne ─────────────────────────────────────────────────
    libraries = {
        "requests":       "requests",
        "feedparser":     "feedparser",
        "beautifulsoup4": "bs4",
        "rich":           "rich",
        "pyyaml":         "yaml",
        "tabulate":       "tabulate",
        "markdown":       "markdown",
        "lxml":           "lxml",
    }
    lib_status: dict[str, bool] = {}
    for lib_name, import_name in libraries.items():
        try:
            __import__(import_name)
            lib_status[lib_name] = True
        except ImportError:
            lib_status[lib_name] = False
    results["libraries"] = lib_status

    # ── Miejsce na dysku (katalog domowy) ─────────────────────────────────────
    try:
        usage = shutil.disk_usage(Path.home())
        results["disk_free_mb"] = round(usage.free / 1024 / 1024, 1)
        results["disk_total_mb"] = round(usage.total / 1024 / 1024, 1)
    except Exception:  # noqa: BLE001
        results["disk_free_mb"]  = None
        results["disk_total_mb"] = None

    # ── Katalog projektu ──────────────────────────────────────────────────────
    results["project_root"] = str(CONFIG["project_root"])
    results["reports_dir"]  = str(CONFIG["reports_dir"])

    return results


def print_environment_report(env: dict[str, Any]) -> None:
    """
    Wyświetla raport ze sprawdzenia środowiska w konsoli przy użyciu Rich.

    Parametry
    ----------
    env : wynik funkcji check_environment()
    """
    console.print(Rule(f"[{COLORS['section']}] ŚRODOWISKO LUMIR AIR v{CONFIG['version']} [/]"))

    table = Table(
        show_header=True,
        header_style=COLORS["header"],
        box=box.ROUNDED,
        expand=False,
        padding=(0, 1),
    )
    table.add_column("Parametr", style="bold white", min_width=24)
    table.add_column("Wartość",  min_width=32)
    table.add_column("Status",   min_width=8, justify="center")

    # Python
    py_icon = "✓" if env["python_ok"] else "✗"
    py_style = COLORS["ok"] if env["python_ok"] else COLORS["error"]
    table.add_row("Python", env["python_version"], f"[{py_style}]{py_icon}[/]")

    # OS
    table.add_row("System", f"{env['platform']} / {env['machine']}", "")

    # Termux
    tmx = "TAK" if env["is_termux"] else "NIE"
    table.add_row("Termux", tmx, "")

    # Narzędzia
    curl_icon = "✓" if env["curl_available"] else "—"
    git_icon  = "✓" if env["git_available"]  else "—"
    table.add_row("curl",    curl_icon, "")
    table.add_row("git",     git_icon,  "")

    # Dysk
    if env["disk_free_mb"] is not None:
        disk_str = f"{env['disk_free_mb']} MB wolne / {env['disk_total_mb']} MB total"
        disk_ok  = env["disk_free_mb"] > 50  # min. 50 MB
        disk_icon = "✓" if disk_ok else "⚠"
        disk_style = COLORS["ok"] if disk_ok else COLORS["warn"]
        table.add_row("Dysk", disk_str, f"[{disk_style}]{disk_icon}[/]")

    console.print(table)

    # Biblioteki
    lib_table = Table(
        title="[bold]Biblioteki zewnętrzne[/]",
        show_header=True,
        header_style=COLORS["header"],
        box=box.SIMPLE_HEAVY,
        expand=False,
        padding=(0, 1),
    )
    lib_table.add_column("Biblioteka", min_width=18)
    lib_table.add_column("Status",     min_width=8, justify="center")

    for lib, ok in env["libraries"].items():
        icon  = "✓" if ok else "✗"
        style = COLORS["ok"] if ok else COLORS["error"]
        lib_table.add_row(lib, f"[{style}]{icon}[/]")

    console.print(lib_table)

    # Ostrzeżenie jeśli Python za stary
    if not env["python_ok"]:
        console.print(
            Panel(
                f"[{COLORS['error']}]Python {env['python_version']} nie spełnia wymagań."
                f" Wymagana wersja >= 3.10[/]",
                title="BŁĄD",
                border_style="red",
            )
        )


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 3 — SPRAWDZANIE INTERNETU
# ═════════════════════════════════════════════════════════════════════════════

def check_internet() -> dict[str, Any]:
    """
    Sprawdza dostępność Internetu poprzez:
      1. Próbę rozwiązania DNS dla kilku znanych hostów
      2. Wysłanie żądania HTTP HEAD do publicznych serwisów

    Zwraca
    ------
    Słownik z wynikami:
        - online (bool)    : czy ogólnie dostęp do sieci jest dostępny
        - latency_ms (int) : opóźnienie do pierwszego odpowiadającego hosta
        - dns_ok (bool)    : czy DNS działa
        - hosts (dict)     : status poszczególnych hostów
    """
    results: dict[str, Any] = {
        "online":      False,
        "latency_ms":  None,
        "dns_ok":      False,
        "hosts":       {},
    }

    test_hosts = [
        ("google.com",       80),
        ("cloudflare.com",   80),
        ("api.github.com",   443),
    ]

    # ── Test DNS (socket) ─────────────────────────────────────────────────────
    for host, port in test_hosts:
        try:
            t0 = time.monotonic()
            socket.setdefaulttimeout(5)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            latency = round((time.monotonic() - t0) * 1000)

            results["hosts"][host] = {"reachable": True, "latency_ms": latency}
            if not results["online"]:
                results["online"]     = True
                results["dns_ok"]     = True
                results["latency_ms"] = latency

        except (socket.timeout, socket.error, OSError):
            results["hosts"][host] = {"reachable": False, "latency_ms": None}

    return results


def print_internet_report(net: dict[str, Any]) -> None:
    """
    Wyświetla raport ze sprawdzenia połączenia internetowego.

    Parametry
    ----------
    net : wynik funkcji check_internet()
    """
    console.print(Rule(f"[{COLORS['section']}] POŁĄCZENIE INTERNETOWE [/]"))

    status_text = "ONLINE" if net["online"] else "OFFLINE"
    status_style = COLORS["ok"] if net["online"] else COLORS["error"]

    table = Table(box=box.ROUNDED, expand=False, padding=(0, 1))
    table.add_column("Host",        style="bold white", min_width=24)
    table.add_column("Osiągalny",   min_width=10, justify="center")
    table.add_column("Latencja ms", min_width=12, justify="right")

    for host, data in net["hosts"].items():
        icon    = "✓" if data["reachable"] else "✗"
        istyle  = COLORS["ok"] if data["reachable"] else COLORS["error"]
        latency = str(data["latency_ms"]) if data["latency_ms"] else "—"
        table.add_row(host, f"[{istyle}]{icon}[/]", latency)

    console.print(table)
    console.print(
        f"Status ogólny: [{status_style}]{status_text}[/] | "
        f"Latencja: [bold]{net['latency_ms'] or '—'} ms[/]"
    )

    if not net["online"]:
        console.print(
            Panel(
                f"[{COLORS['error']}]Brak połączenia z Internetem. "
                "Sprawdź sieć Wi-Fi lub dane mobilne.[/]",
                title="BŁĄD SIECI",
                border_style="red",
            )
        )


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 4 — GITHUB API
# ═════════════════════════════════════════════════════════════════════════════

def get_github_headers() -> dict[str, str]:
    """
    Zwraca nagłówki HTTP dla GitHub API.

    Jeśli ustawiona jest zmienna środowiskowa GITHUB_TOKEN, dodaje autoryzację
    Bearer, co podnosi limit zapytań z 60 do 5000 na godzinę.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_github_trending(session: requests.Session) -> list[dict[str, Any]]:
    """
    Pobiera listę popularnych repozytoriów Pythona z GitHub Search API.

    Endpoint: GET /search/repositories
    Sortowanie: gwiazdki malejąco

    Zwraca
    ------
    Listę słowników z kluczami:
        name, full_name, description, stars, forks, language,
        url, updated_at, topics, license
    """
    url = f"{CONFIG['github_api_base']}/search/repositories"
    params = {
        "q":        CONFIG["github_search_query"],
        "sort":     "stars",
        "order":    "desc",
        "per_page": CONFIG["github_search_limit"],
        "page":     1,
    }

    data = safe_get(
        session, url,
        params=params,
        extra_headers=get_github_headers(),
    )

    if not data or "items" not in data:
        return []

    repos = []
    for item in data["items"]:
        license_name = None
        if item.get("license") and isinstance(item["license"], dict):
            license_name = item["license"].get("name")

        repos.append({
            "name":        item.get("name", ""),
            "full_name":   item.get("full_name", ""),
            "description": item.get("description") or "",
            "stars":       item.get("stargazers_count", 0),
            "forks":       item.get("forks_count", 0),
            "language":    item.get("language") or "—",
            "url":         item.get("html_url", ""),
            "updated_at":  item.get("updated_at", ""),
            "topics":      item.get("topics", []),
            "license":     license_name or "—",
        })

    return repos


def fetch_github_rate_limit(session: requests.Session) -> dict[str, Any]:
    """
    Sprawdza aktualny limit zapytań do GitHub API.

    Endpoint: GET /rate_limit

    Zwraca
    ------
    Słownik z informacją o limicie core i search:
        core_remaining, core_limit, core_reset
        search_remaining, search_limit, search_reset
    """
    url = f"{CONFIG['github_api_base']}/rate_limit"
    data = safe_get(session, url, extra_headers=get_github_headers())

    if not data or "resources" not in data:
        return {}

    core   = data["resources"].get("core",   {})
    search = data["resources"].get("search", {})

    def fmt_reset(ts: Optional[int]) -> str:
        """Zamienia timestamp UNIX na czytelny czas UTC."""
        if not ts:
            return "—"
        return datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M:%S UTC")

    return {
        "core_remaining":   core.get("remaining", "—"),
        "core_limit":       core.get("limit",     "—"),
        "core_reset":       fmt_reset(core.get("reset")),
        "search_remaining": search.get("remaining", "—"),
        "search_limit":     search.get("limit",     "—"),
        "search_reset":     fmt_reset(search.get("reset")),
    }


def print_github_report(repos: list[dict], rate: dict) -> None:
    """
    Wyświetla dane z GitHub API w konsoli jako sformatowaną tabelę Rich.

    Parametry
    ----------
    repos : wynik fetch_github_trending()
    rate  : wynik fetch_github_rate_limit()
    """
    console.print(Rule(f"[{COLORS['section']}] GITHUB — TRENDING PYTHON REPOS [/]"))

    if not repos:
        console.print(f"[{COLORS['warn']}]Brak danych z GitHub API.[/]")
        return

    # Tabela repozytoriów
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style=COLORS["header"],
        expand=True,
        padding=(0, 1),
    )
    table.add_column("#",           width=3,  justify="right")
    table.add_column("Repozytorium", min_width=28)
    table.add_column("⭐ Stars",     width=10, justify="right")
    table.add_column("🍴 Forks",     width=10, justify="right")
    table.add_column("Lang",         width=10)
    table.add_column("Opis",         min_width=30)

    for idx, repo in enumerate(repos, start=1):
        table.add_row(
            str(idx),
            repo["full_name"],
            format_number(repo["stars"]),
            format_number(repo["forks"]),
            repo["language"],
            truncate_text(repo["description"], 60),
        )

    console.print(table)

    # Limit API
    if rate:
        console.print(
            f"[{COLORS['muted']}]Rate limit — core: "
            f"{rate.get('core_remaining')}/{rate.get('core_limit')} "
            f"(reset {rate.get('core_reset')}) | "
            f"search: {rate.get('search_remaining')}/{rate.get('search_limit')} "
            f"(reset {rate.get('search_reset')})[/]"
        )


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 5 — HACKER NEWS
# ═════════════════════════════════════════════════════════════════════════════

def fetch_hacker_news(session: requests.Session) -> list[dict[str, Any]]:
    """
    Pobiera najnowsze posty z Hacker News pasujące do zapytania,
    używając Algolia HN Search API.

    Endpoint: https://hn.algolia.com/api/v1/search

    Zwraca
    ------
    Listę słowników z kluczami:
        title, url, author, points, comments, created_at, hn_url
    """
    url = CONFIG["hn_api_url"]
    params = {
        "query":    CONFIG["hn_query"],
        "tags":     "story",
        "hitsPerPage": CONFIG["hn_limit"],
    }

    data = safe_get(session, url, params=params)

    if not data or "hits" not in data:
        return []

    stories = []
    for hit in data["hits"]:
        obj_id  = hit.get("objectID", "")
        hn_url  = f"https://news.ycombinator.com/item?id={obj_id}" if obj_id else ""

        stories.append({
            "title":      hit.get("title") or hit.get("story_title") or "—",
            "url":        hit.get("url") or hn_url,
            "author":     hit.get("author", "—"),
            "points":     hit.get("points", 0) or 0,
            "comments":   hit.get("num_comments", 0) or 0,
            "created_at": hit.get("created_at", ""),
            "hn_url":     hn_url,
        })

    # Sortuj malejąco po punktach
    stories.sort(key=lambda s: s["points"], reverse=True)
    return stories


def print_hn_report(stories: list[dict]) -> None:
    """
    Wyświetla dane z Hacker News w konsoli jako tabelę Rich.

    Parametry
    ----------
    stories : wynik fetch_hacker_news()
    """
    console.print(Rule(f"[{COLORS['section']}] HACKER NEWS — {CONFIG['hn_query'].upper()} [/]"))

    if not stories:
        console.print(f"[{COLORS['warn']}]Brak danych z Hacker News.[/]")
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style=COLORS["header"],
        expand=True,
        padding=(0, 1),
    )
    table.add_column("#",        width=3, justify="right")
    table.add_column("Tytuł",    min_width=40)
    table.add_column("Autor",    min_width=14)
    table.add_column("▲ Pts",    width=8,  justify="right")
    table.add_column("💬",        width=6,  justify="right")
    table.add_column("Data",     width=12)

    for idx, story in enumerate(stories, start=1):
        date_str = story["created_at"][:10] if story["created_at"] else "—"
        table.add_row(
            str(idx),
            truncate_text(story["title"], 55),
            story["author"],
            str(story["points"]),
            str(story["comments"]),
            date_str,
        )

    console.print(table)


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 6 — REDDIT JSON API
# ═════════════════════════════════════════════════════════════════════════════

def fetch_reddit_subreddit(
    session: requests.Session,
    subreddit: str,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """
    Pobiera posty z danego subredditu przez publiczne Reddit JSON API
    (bez autoryzacji OAuth).

    URL: https://www.reddit.com/r/{subreddit}/hot.json

    Parametry
    ----------
    session   : aktywna sesja HTTP
    subreddit : nazwa subredditu (bez prefiksu r/)
    limit     : maksymalna liczba postów

    Zwraca
    ------
    Listę słowników z kluczami:
        title, author, score, comments, subreddit, url, permalink,
        created_utc, flair
    """
    url = f"https://www.reddit.com/r/{subreddit}/hot.json"
    params = {"limit": limit}

    # Reddit wymaga User-Agent innego niż przeglądarka — już ustawiony w sesji
    data = safe_get(session, url, params=params)

    if not data:
        return []

    # Struktura odpowiedzi: data -> children -> [data, ...]
    try:
        children = data["data"]["children"]
    except (KeyError, TypeError):
        return []

    posts = []
    for child in children:
        post = child.get("data", {})
        posts.append({
            "title":       post.get("title", "—"),
            "author":      post.get("author", "—"),
            "score":       post.get("score", 0),
            "comments":    post.get("num_comments", 0),
            "subreddit":   post.get("subreddit", subreddit),
            "url":         post.get("url", ""),
            "permalink":   "https://reddit.com" + post.get("permalink", ""),
            "created_utc": post.get("created_utc", 0),
            "flair":       post.get("link_flair_text") or "",
        })

    return posts


def fetch_all_reddit(session: requests.Session) -> dict[str, list[dict]]:
    """
    Pobiera posty ze wszystkich skonfigurowanych subredditów.

    Iteruje przez listę CONFIG['reddit_subreddits'] i zbiera dane
    dla każdego z nich.

    Zwraca
    ------
    Słownik {nazwa_subredditu: lista_postów}
    """
    all_posts: dict[str, list[dict]] = {}

    for sub in CONFIG["reddit_subreddits"]:
        posts = fetch_reddit_subreddit(
            session, sub, limit=CONFIG["reddit_limit"]
        )
        all_posts[sub] = posts
        # Krótka przerwa by nie wywołać blokady rate-limit
        time.sleep(0.5)

    return all_posts


def print_reddit_report(reddit_data: dict[str, list[dict]]) -> None:
    """
    Wyświetla dane z Reddita w konsoli jako serie tabel Rich.

    Parametry
    ----------
    reddit_data : wynik fetch_all_reddit()
    """
    console.print(Rule(f"[{COLORS['section']}] REDDIT — HOT POSTS [/]"))

    if not reddit_data:
        console.print(f"[{COLORS['warn']}]Brak danych z Reddit.[/]")
        return

    for sub, posts in reddit_data.items():
        console.print(f"\n[{COLORS['accent']}]r/{sub}[/]")

        if not posts:
            console.print(f"  [{COLORS['muted']}]Brak postów.[/]")
            continue

        table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style=COLORS["header"],
            expand=True,
            padding=(0, 1),
        )
        table.add_column("#",      width=3, justify="right")
        table.add_column("Tytuł", min_width=40)
        table.add_column("Autor", min_width=14)
        table.add_column("▲",     width=7, justify="right")
        table.add_column("💬",     width=6, justify="right")

        for idx, post in enumerate(posts, start=1):
            table.add_row(
                str(idx),
                truncate_text(post["title"], 55),
                post["author"],
                format_number(post["score"]),
                format_number(post["comments"]),
            )

        console.print(table)


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 7 — HUGGING FACE API
# ═════════════════════════════════════════════════════════════════════════════

def fetch_huggingface_models(session: requests.Session) -> list[dict[str, Any]]:
    """
    Pobiera listę najpopularniejszych modeli z Hugging Face Hub API.

    Endpoint: GET https://huggingface.co/api/models

    Sortowanie i filtrowanie:
      - sort    : CONFIG['hf_sort'] (downloads, trending, likes, created_at)
      - limit   : CONFIG['hf_models_limit']
      - direction: -1 (malejąco)

    Zwraca
    ------
    Listę słowników z kluczami:
        id, author, model_name, downloads, likes, pipeline_tag,
        last_modified, tags, private
    """
    url = f"{CONFIG['hf_api_base']}/models"
    params = {
        "sort":      CONFIG["hf_sort"],
        "direction": -1,
        "limit":     CONFIG["hf_models_limit"],
        "full":      "False",
    }

    data = safe_get(session, url, params=params)

    if not data or not isinstance(data, list):
        return []

    models = []
    for item in data:
        model_id = item.get("id", "")
        author, _, model_name = model_id.partition("/")

        models.append({
            "id":            model_id,
            "author":        author,
            "model_name":    model_name or model_id,
            "downloads":     item.get("downloads", 0) or 0,
            "likes":         item.get("likes",     0) or 0,
            "pipeline_tag":  item.get("pipeline_tag") or "—",
            "last_modified": item.get("lastModified", "")[:10],
            "tags":          item.get("tags", [])[:5],  # max 5 tagów
            "private":       item.get("private", False),
        })

    return models


def fetch_huggingface_spaces(session: requests.Session) -> list[dict[str, Any]]:
    """
    Pobiera listę popularnych Spaces z Hugging Face Hub API.

    Endpoint: GET https://huggingface.co/api/spaces

    Zwraca
    ------
    Listę słowników z kluczami:
        id, author, space_name, likes, sdk, last_modified
    """
    url = f"{CONFIG['hf_api_base']}/spaces"
    params = {
        "sort":      "likes",
        "direction": -1,
        "limit":     5,
        "full":      "False",
    }

    data = safe_get(session, url, params=params)

    if not data or not isinstance(data, list):
        return []

    spaces = []
    for item in data:
        space_id = item.get("id", "")
        author, _, space_name = space_id.partition("/")
        spaces.append({
            "id":            space_id,
            "author":        author,
            "space_name":    space_name or space_id,
            "likes":         item.get("likes", 0) or 0,
            "sdk":           item.get("sdk") or "—",
            "last_modified": item.get("lastModified", "")[:10],
        })

    return spaces


def print_huggingface_report(
    models: list[dict],
    spaces: list[dict],
) -> None:
    """
    Wyświetla dane z Hugging Face Hub w konsoli.

    Parametry
    ----------
    models : wynik fetch_huggingface_models()
    spaces : wynik fetch_huggingface_spaces()
    """
    console.print(Rule(f"[{COLORS['section']}] HUGGING FACE — TOP MODELS & SPACES [/]"))

    # ── Modele ────────────────────────────────────────────────────────────────
    if models:
        console.print(f"[{COLORS['accent']}]Top modele (sort: {CONFIG['hf_sort']})[/]")
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style=COLORS["header"],
            expand=True,
            padding=(0, 1),
        )
        table.add_column("#",          width=3,  justify="right")
        table.add_column("Model ID",   min_width=30)
        table.add_column("Task",       min_width=20)
        table.add_column("⬇ Pobrania", width=12, justify="right")
        table.add_column("❤ Likes",    width=10, justify="right")
        table.add_column("Data",       width=11)

        for idx, m in enumerate(models, start=1):
            table.add_row(
                str(idx),
                truncate_text(m["id"], 36),
                m["pipeline_tag"],
                format_number(m["downloads"]),
                format_number(m["likes"]),
                m["last_modified"],
            )

        console.print(table)
    else:
        console.print(f"[{COLORS['warn']}]Brak danych o modelach HF.[/]")

    # ── Spaces ────────────────────────────────────────────────────────────────
    if spaces:
        console.print(f"\n[{COLORS['accent']}]Top Spaces[/]")
        sp_table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style=COLORS["header"],
            expand=False,
            padding=(0, 1),
        )
        sp_table.add_column("#",        width=3, justify="right")
        sp_table.add_column("Space ID", min_width=30)
        sp_table.add_column("SDK",      min_width=10)
        sp_table.add_column("❤ Likes",  width=10, justify="right")
        sp_table.add_column("Data",     width=11)

        for idx, s in enumerate(spaces, start=1):
            sp_table.add_row(
                str(idx),
                truncate_text(s["id"], 36),
                s["sdk"],
                format_number(s["likes"]),
                s["last_modified"],
            )

        console.print(sp_table)


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 8 — GENEROWANIE RAPORTU MARKDOWN
# ═════════════════════════════════════════════════════════════════════════════

def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """
    Generuje tabelę Markdown przy użyciu biblioteki tabulate.

    Parametry
    ----------
    headers : nagłówki kolumn
    rows    : wiersze danych (list of lists)

    Zwraca
    ------
    Ciąg znaków w formacie Markdown (pipe table).
    """
    return tabulate(rows, headers=headers, tablefmt="pipe")


def _section(title: str, level: int = 2) -> str:
    """
    Zwraca nagłówek sekcji Markdown.

    Parametry
    ----------
    title : tekst nagłówka
    level : poziom nagłówka (1–6), domyślnie 2 (##)
    """
    prefix = "#" * level
    return f"\n{prefix} {title}\n"


def generate_markdown_report(
    env:         dict,
    net:         dict,
    github_repos: list[dict],
    github_rate: dict,
    hn_stories:  list[dict],
    reddit_data: dict[str, list[dict]],
    hf_models:   list[dict],
    hf_spaces:   list[dict],
) -> str:
    """
    Generuje kompletny raport Markdown agregujący dane ze wszystkich źródeł.

    Raport składa się z sekcji:
      1. Nagłówek z metadanymi (wersja, data, środowisko)
      2. Status środowiska i sieci
      3. GitHub Trending
      4. Hacker News
      5. Reddit
      6. Hugging Face
      7. Stopka

    Parametry
    ----------
    env          : wynik check_environment()
    net          : wynik check_internet()
    github_repos : wynik fetch_github_trending()
    github_rate  : wynik fetch_github_rate_limit()
    hn_stories   : wynik fetch_hacker_news()
    reddit_data  : wynik fetch_all_reddit()
    hf_models    : wynik fetch_huggingface_models()
    hf_spaces    : wynik fetch_huggingface_spaces()

    Zwraca
    ------
    Ciąg znaków z pełnym raportem w formacie Markdown.
    """
    ts_utc   = now_iso()
    ts_local = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: list[str] = []

    # ─────────────────────────────────────────────────────────────────────────
    # 0. YAML Front Matter (opcjonalne metadane)
    # ─────────────────────────────────────────────────────────────────────────
    meta = {
        "title":     f"{CONFIG['app_name']} v{CONFIG['version']} — Raport",
        "version":   CONFIG["version"],
        "generated": ts_utc,
        "python":    env.get("python_version", "—"),
        "platform":  env.get("platform", "—"),
    }
    lines.append("---")
    lines.append(yaml.dump(meta, default_flow_style=False, allow_unicode=True).strip())
    lines.append("---")
    lines.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # 1. TYTUŁ GŁÓWNY
    # ─────────────────────────────────────────────────────────────────────────
    lines.append(f"# {CONFIG['app_name']} v{CONFIG['version']} — Intelligence Radar")
    lines.append("")
    lines.append(f"> Wygenerowano: **{ts_local}** (lokalny) | **{ts_utc}** (UTC)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # 2. ŚRODOWISKO
    # ─────────────────────────────────────────────────────────────────────────
    lines.append(_section("Środowisko", 2))

    env_rows = [
        ["Python",    env.get("python_version", "—"), "✓" if env.get("python_ok") else "✗"],
        ["System",    f"{env.get('platform','—')} / {env.get('machine','—')}", ""],
        ["Termux",    "TAK" if env.get("is_termux") else "NIE", ""],
        ["Dysk wolny",
         f"{env.get('disk_free_mb','—')} MB" if env.get("disk_free_mb") else "—", ""],
    ]
    lines.append(_md_table(["Parametr", "Wartość", "Status"], env_rows))
    lines.append("")

    # Biblioteki
    lines.append("### Biblioteki zewnętrzne\n")
    lib_rows = [
        [lib, "✓" if ok else "✗"]
        for lib, ok in env.get("libraries", {}).items()
    ]
    lines.append(_md_table(["Biblioteka", "Status"], lib_rows))
    lines.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # 3. INTERNET
    # ─────────────────────────────────────────────────────────────────────────
    lines.append(_section("Połączenie internetowe", 2))

    online_str = "✅ ONLINE" if net.get("online") else "❌ OFFLINE"
    latency    = net.get("latency_ms")
    lines.append(f"**Status:** {online_str}  ")
    lines.append(f"**Latencja:** {latency} ms\n" if latency else "**Latencja:** —\n")

    host_rows = [
        [
            host,
            "✓" if data["reachable"] else "✗",
            f"{data['latency_ms']} ms" if data.get("latency_ms") else "—",
        ]
        for host, data in net.get("hosts", {}).items()
    ]
    if host_rows:
        lines.append(_md_table(["Host", "Osiągalny", "Latencja"], host_rows))
    lines.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # 4. GITHUB TRENDING
    # ─────────────────────────────────────────────────────────────────────────
    lines.append(_section("GitHub — Trending Python Repos", 2))

    if github_rate:
        lines.append(
            f"> Rate limit — core: {github_rate.get('core_remaining')}/"
            f"{github_rate.get('core_limit')} "
            f"(reset {github_rate.get('core_reset')}) | "
            f"search: {github_rate.get('search_remaining')}/"
            f"{github_rate.get('search_limit')}\n"
        )

    if github_repos:
        gh_rows = [
            [
                str(i),
                f"[{r['full_name']}]({r['url']})",
                format_number(r["stars"]),
                format_number(r["forks"]),
                r["language"],
                truncate_text(r["description"], 80),
            ]
            for i, r in enumerate(github_repos, start=1)
        ]
        lines.append(
            _md_table(
                ["#", "Repozytorium", "⭐ Stars", "🍴 Forks", "Język", "Opis"],
                gh_rows,
            )
        )
    else:
        lines.append("_Brak danych._")
    lines.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # 5. HACKER NEWS
    # ─────────────────────────────────────────────────────────────────────────
    lines.append(_section(f"Hacker News — {CONFIG['hn_query']}", 2))

    if hn_stories:
        hn_rows = [
            [
                str(i),
                f"[{truncate_text(s['title'], 70)}]({s['url']})" if s["url"] else truncate_text(s["title"], 70),
                s["author"],
                str(s["points"]),
                str(s["comments"]),
                s["created_at"][:10] if s["created_at"] else "—",
            ]
            for i, s in enumerate(hn_stories, start=1)
        ]
        lines.append(
            _md_table(
                ["#", "Tytuł", "Autor", "▲ Pts", "💬", "Data"],
                hn_rows,
            )
        )
    else:
        lines.append("_Brak danych._")
    lines.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # 6. REDDIT
    # ─────────────────────────────────────────────────────────────────────────
    lines.append(_section("Reddit — Hot Posts", 2))

    if reddit_data:
        for sub, posts in reddit_data.items():
            lines.append(f"### r/{sub}\n")
            if posts:
                r_rows = [
                    [
                        str(i),
                        f"[{truncate_text(p['title'], 65)}]({p['permalink']})",
                        p["author"],
                        format_number(p["score"]),
                        format_number(p["comments"]),
                    ]
                    for i, p in enumerate(posts, start=1)
                ]
                lines.append(
                    _md_table(["#", "Tytuł", "Autor", "▲", "💬"], r_rows)
                )
            else:
                lines.append("_Brak postów._")
            lines.append("")
    else:
        lines.append("_Brak danych._")
        lines.append("")

    # ─────────────────────────────────────────────────────────────────────────
    # 7. HUGGING FACE
    # ─────────────────────────────────────────────────────────────────────────
    lines.append(_section("Hugging Face — Top Models & Spaces", 2))

    if hf_models:
        lines.append(f"### Modele (sort: {CONFIG['hf_sort']})\n")
        hf_rows = [
            [
                str(i),
                f"[{m['id']}](https://huggingface.co/{m['id']})",
                m["pipeline_tag"],
                format_number(m["downloads"]),
                format_number(m["likes"]),
                m["last_modified"],
            ]
            for i, m in enumerate(hf_models, start=1)
        ]
        lines.append(
            _md_table(
                ["#", "Model ID", "Task", "⬇ Pobrania", "❤ Likes", "Data"],
                hf_rows,
            )
        )
        lines.append("")
    else:
        lines.append("_Brak danych o modelach._\n")

    if hf_spaces:
        lines.append("### Spaces\n")
        sp_rows = [
            [
                str(i),
                f"[{s['id']}](https://huggingface.co/spaces/{s['id']})",
                s["sdk"],
                format_number(s["likes"]),
                s["last_modified"],
            ]
            for i, s in enumerate(hf_spaces, start=1)
        ]
        lines.append(
            _md_table(["#", "Space ID", "SDK", "❤ Likes", "Data"], sp_rows)
        )
        lines.append("")
    else:
        lines.append("_Brak danych o Spaces._\n")

    # ─────────────────────────────────────────────────────────────────────────
    # 8. STOPKA
    # ─────────────────────────────────────────────────────────────────────────
    lines.append("---")
    lines.append("")
    lines.append(
        f"*{CONFIG['app_name']} v{CONFIG['version']} — "
        f"wygenerowano automatycznie {ts_utc}*"
    )

    return "\n".join(lines)


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 9 — ZAPIS RAPORTU DO PLIKU
# ═════════════════════════════════════════════════════════════════════════════

def ensure_directories() -> None:
    """
    Tworzy katalogi projektu i raportów, jeśli nie istnieją.

    Katalogi:
      - ~/lumir_air_v13/
      - ~/lumir_air_v13/reports/

    Używa Path.mkdir(parents=True, exist_ok=True), więc jest idempotentna —
    wywołanie jej wiele razy nie powoduje błędów.
    """
    CONFIG["project_root"].mkdir(parents=True, exist_ok=True)
    CONFIG["reports_dir"].mkdir(parents=True, exist_ok=True)
    console.print(
        f"[{COLORS['ok']}]✓[/] Katalogi projektu: {CONFIG['project_root']}"
    )


def save_report(markdown_content: str) -> Path:
    """
    Zapisuje raport Markdown do katalogu reports/.

    Nazwa pliku zawiera datę i czas w formacie:
      radar_YYYY-MM-DD_HHMMSS.md

    Parametry
    ----------
    markdown_content : ciąg znaków z raportem Markdown

    Zwraca
    ------
    Obiekt Path wskazujący na zapisany plik.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filename  = f"radar_{timestamp}.md"
    filepath  = CONFIG["reports_dir"] / filename

    try:
        filepath.write_text(markdown_content, encoding="utf-8")
        console.print(
            f"[{COLORS['ok']}]✓[/] Raport zapisany: [bold]{filepath}[/]"
        )
    except OSError as exc:
        console.print(
            f"[{COLORS['error']}]✗  Nie można zapisać raportu: {exc}[/]"
        )

    return filepath


def list_reports() -> list[Path]:
    """
    Zwraca posortowaną listę wszystkich raportów w katalogu reports/
    (pliki .md, od najnowszego).

    Zwraca
    ------
    Listę obiektów Path.
    """
    reports_dir = CONFIG["reports_dir"]
    if not reports_dir.exists():
        return []

    files = sorted(reports_dir.glob("radar_*.md"), reverse=True)
    return files


def print_reports_list() -> None:
    """
    Wyświetla listę istniejących raportów w katalogu reports/
    jako tabelę Rich.
    """
    files = list_reports()

    console.print(Rule(f"[{COLORS['section']}] ZAPISANE RAPORTY [/]"))

    if not files:
        console.print(f"[{COLORS['muted']}]Brak zapisanych raportów.[/]")
        return

    table = Table(box=box.SIMPLE_HEAVY, expand=False, padding=(0, 1))
    table.add_column("#",    width=4, justify="right")
    table.add_column("Plik", min_width=40)
    table.add_column("Rozmiar", width=12, justify="right")

    for idx, fp in enumerate(files, start=1):
        size_kb = round(fp.stat().st_size / 1024, 1)
        table.add_row(str(idx), fp.name, f"{size_kb} KB")

    console.print(table)


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 10 — BANNER I PREZENTACJA
# ═════════════════════════════════════════════════════════════════════════════

def print_banner() -> None:
    """
    Wyświetla baner startowy LUMIR AIR v13 przy użyciu Rich Panel.
    Baner zawiera nazwę, wersję i informację o autorze.
    """
    banner_text = Text(justify="center")
    banner_text.append(
        f"  ██╗     ██╗   ██╗███╗   ███╗██╗██████╗      █████╗ ██╗██████╗  \n",
        style="bold cyan",
    )
    banner_text.append(
        f"  ██║     ██║   ██║████╗ ████║██║██╔══██╗    ██╔══██╗██║██╔══██╗ \n",
        style="bold cyan",
    )
    banner_text.append(
        f"  ██║     ██║   ██║██╔████╔██║██║██████╔╝    ███████║██║██████╔╝ \n",
        style="bold cyan",
    )
    banner_text.append(
        f"  ██║     ██║   ██║██║╚██╔╝██║██║██╔══██╗    ██╔══██║██║██╔══██╗ \n",
        style="bold cyan",
    )
    banner_text.append(
        f"  ███████╗╚██████╔╝██║ ╚═╝ ██║██║██║  ██║    ██║  ██║██║██║  ██║ \n",
        style="bold cyan",
    )
    banner_text.append(
        f"  ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ \n",
        style="bold cyan",
    )
    banner_text.append(
        f"\n           v{CONFIG['version']}  ·  Intelligence Radar  ·  Termux / Android\n",
        style="bold white",
    )

    console.print(
        Panel(
            banner_text,
            border_style="cyan",
            padding=(0, 2),
        )
    )


def print_summary(report_path: Path) -> None:
    """
    Wyświetla podsumowanie po zakończeniu przebiegu programu.

    Pokazuje ścieżkę do wygenerowanego raportu i czas wykonania.

    Parametry
    ----------
    report_path : ścieżka do zapisanego raportu
    """
    console.print("")
    console.print(
        Panel(
            f"[{COLORS['ok']}]✓ Raport gotowy[/]\n\n"
            f"[bold]Plik:[/] {report_path}\n"
            f"[bold]Czas:[/] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title=f"[bold]{CONFIG['app_name']} v{CONFIG['version']} — ZAKOŃCZONO[/]",
            border_style="green",
        )
    )


# ═════════════════════════════════════════════════════════════════════════════
# SEKCJA 11 — GŁÓWNA PĘTLA PROGRAMU (main)
# ═════════════════════════════════════════════════════════════════════════════

def main() -> int:
    """
    Główna funkcja programu LUMIR AIR v13.

    Przepływ działania:
      1. Wyświetl baner
      2. Utwórz katalogi projektu
      3. Sprawdź środowisko
      4. Sprawdź Internet
      5. Pobierz dane z GitHub API
      6. Pobierz dane z Hacker News
      7. Pobierz dane z Reddit
      8. Pobierz dane z Hugging Face
      9. Wygeneruj raport Markdown
     10. Zapisz raport
     11. Wyświetl listę raportów
     12. Podsumowanie

    Zwraca
    ------
    Kod wyjścia: 0 = sukces, 1 = błąd krytyczny
    """
    t_start = time.monotonic()

    # ── Baner ─────────────────────────────────────────────────────────────────
    print_banner()

    # ── Katalogi ──────────────────────────────────────────────────────────────
    ensure_directories()

    # ── Sesja HTTP ────────────────────────────────────────────────────────────
    session = make_http_session()

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 1 — ŚRODOWISKO
    # ─────────────────────────────────────────────────────────────────────────
    console.print("")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Sprawdzam środowisko…", total=None)
        env = check_environment()
        progress.update(task, completed=True)

    print_environment_report(env)

    # Sprawdź wersję Pythona — kryterium krytyczne
    if not env["python_ok"]:
        console.print(
            f"[{COLORS['error']}]KRYTYCZNY BŁĄD: Wymagany Python >= 3.10. "
            f"Masz {env['python_version']}[/]"
        )
        return 1

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 2 — INTERNET
    # ─────────────────────────────────────────────────────────────────────────
    console.print("")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Sprawdzam połączenie internetowe…", total=None)
        net = check_internet()
        progress.update(task, completed=True)

    print_internet_report(net)

    if not net["online"]:
        console.print(
            f"[{COLORS['error']}]KRYTYCZNY BŁĄD: Brak dostępu do Internetu. "
            "Program nie może pobrać danych.[/]"
        )
        return 1

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 3 — GITHUB API
    # ─────────────────────────────────────────────────────────────────────────
    console.print("")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Pobieram dane z GitHub API…", total=None)
        github_repos = fetch_github_trending(session)
        github_rate  = fetch_github_rate_limit(session)
        progress.update(task, completed=True)

    print_github_report(github_repos, github_rate)

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 4 — HACKER NEWS
    # ─────────────────────────────────────────────────────────────────────────
    console.print("")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Pobieram Hacker News…", total=None)
        hn_stories = fetch_hacker_news(session)
        progress.update(task, completed=True)

    print_hn_report(hn_stories)

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 5 — REDDIT
    # ─────────────────────────────────────────────────────────────────────────
    console.print("")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Pobieram Reddit JSON…", total=None)
        reddit_data = fetch_all_reddit(session)
        progress.update(task, completed=True)

    print_reddit_report(reddit_data)

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 6 — HUGGING FACE
    # ─────────────────────────────────────────────────────────────────────────
    console.print("")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Pobieram Hugging Face API…", total=None)
        hf_models = fetch_huggingface_models(session)
        hf_spaces = fetch_huggingface_spaces(session)
        progress.update(task, completed=True)

    print_huggingface_report(hf_models, hf_spaces)

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 7 — GENEROWANIE RAPORTU MARKDOWN
    # ─────────────────────────────────────────────────────────────────────────
    console.print("")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Generuję raport Markdown…", total=None)
        md_content = generate_markdown_report(
            env=env,
            net=net,
            github_repos=github_repos,
            github_rate=github_rate,
            hn_stories=hn_stories,
            reddit_data=reddit_data,
            hf_models=hf_models,
            hf_spaces=hf_spaces,
        )
        progress.update(task, completed=True)

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 8 — ZAPIS RAPORTU
    # ─────────────────────────────────────────────────────────────────────────
    report_path = save_report(md_content)

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 9 — LISTA RAPORTÓW
    # ─────────────────────────────────────────────────────────────────────────
    console.print("")
    print_reports_list()

    # ─────────────────────────────────────────────────────────────────────────
    # KROK 10 — PODSUMOWANIE
    # ─────────────────────────────────────────────────────────────────────────
    elapsed = round(time.monotonic() - t_start, 2)
    console.print(f"\n[{COLORS['muted']}]Całkowity czas wykonania: {elapsed} s[/]")
    print_summary(report_path)

    return 0


# ═════════════════════════════════════════════════════════════════════════════
# PUNKT WEJŚCIA
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sys.exit(main())
