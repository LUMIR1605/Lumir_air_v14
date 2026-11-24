"""No scans: check the patched, pinned environment with network/process guards."""
import socket
import subprocess
import importlib.metadata
from holehe import core
assert importlib.metadata.version("holehe") == "1.61"
def blocked(*args, **kwargs): raise RuntimeError("OFFLINE CHECK")
socket.socket.connect = blocked
socket.getaddrinfo = blocked
subprocess.Popen = blocked
core.check_update()
assert "httpx.get" not in __import__("inspect").getsource(core.check_update)
print("Holehe 1.61: auto-update disabled; modules:",len(core.import_submodules("holehe.modules")))
