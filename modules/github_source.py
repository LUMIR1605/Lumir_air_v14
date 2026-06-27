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
