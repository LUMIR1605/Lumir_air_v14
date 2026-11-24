"""Patch only an isolated Holehe 1.61 environment, without running CLI."""
from pathlib import Path
import importlib.metadata
import holehe.core
assert importlib.metadata.version("holehe") == "1.61"
p=Path(holehe.core.__file__)
s=p.read_text()
start=s.index("def check_update():")
end=s.index("\ndef credit():", start)
backup=p.with_suffix(".py.rc7-original")
if not backup.exists(): backup.write_text(s)
p.write_text(s[:start]+"def check_update():\n    return None  # RC7: no automatic updates\n"+s[end:])
