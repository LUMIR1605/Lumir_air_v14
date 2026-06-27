import ast
from pathlib import Path

SOURCE = Path("radar_reference.py")

tree = ast.parse(SOURCE.read_text(encoding="utf-8"))

groups = {
    "system": [],
    "github": [],
    "hackernews": [],
    "reddit": [],
    "huggingface": [],
    "report": [],
}

for node in tree.body:
    if not isinstance(node, ast.FunctionDef):
        continue

    n = node.name

    if "github" in n:
        groups["github"].append(n)

    elif "hacker" in n or n.startswith("print_hn"):
        groups["hackernews"].append(n)

    elif "reddit" in n:
        groups["reddit"].append(n)

    elif "huggingface" in n:
        groups["huggingface"].append(n)

    elif (
        "report" in n
        or "markdown" in n
        or "summary" in n
        or "reports" in n
        or "save_report" in n
    ):
        groups["report"].append(n)

    else:
        groups["system"].append(n)

print()

for module, funcs in groups.items():
    print("=" * 60)
    print(module.upper())
    print("=" * 60)
    for f in funcs:
        print(" ", f)
