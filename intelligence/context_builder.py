def build(repos, hackernews, models, news):
    lines = []

    lines.append("=== RAPORT LUMIR ===\n")

    lines.append("=== GITHUB ===")
    for r in repos[:3]:
        lines.append(f"Repozytorium: {r.get('full_name','')}")
        if r.get("description"):
            lines.append(f"Opis: {r['description']}")
        lines.append("")

    lines.append("=== HACKER NEWS ===")
    for h in hackernews[:3]:
        lines.append(f"Tytuł: {h.get('title','')}")
        if h.get("url"):
            lines.append(f"Link: {h['url']}")
        lines.append("")

    lines.append("=== MODELE AI ===")
    for m in models[:3]:
        lines.append(f"Model: {m.get('id','')}")
        lines.append("")

    lines.append("=== AI NEWS ===")
    for n in news[:5]:
        lines.append(f"Temat: {n.get('title','')}")
        if n.get("summary"):
            lines.append(f"Opis: {n['summary']}")
        lines.append("")

    lines.append("=== ZADANIE DLA LUMIR ===")
    lines.append(
        "Połącz wszystkie informacje. "
        "Znajdź wspólne motywy. "
        "Wskaż manipulacje, okazje biznesowe, trendy, "
        "pomysły na filmy, muzykę i edukację. "
        "Myśl jak strateg, a nie jak zwykły generator tekstu."
    )

    return "\n".join(lines)
