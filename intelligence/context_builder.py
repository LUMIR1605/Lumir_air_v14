def build(repos, hackernews, models, news):
    lines = []

    lines.append("TRENDY:")

    for r in repos[:2]:
        lines.append(f"GitHub: {r.get('full_name','')}")

    for h in hackernews[:2]:
        lines.append(f"HN: {h.get('title','')}")

    for m in models[:2]:
        lines.append(f"Model: {m.get('id','')}")

    for n in news[:3]:
        lines.append(f"News: {n.get('title','')}")

    return "\n".join(lines)
