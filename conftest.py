"""Offline-only test suite, including collection. No real sources or subprocesses."""
import socket
import subprocess

def _blocked(*args, **kwargs):
    raise RuntimeError("Offline test suite: network/process execution blocked")

def pytest_configure(config):
    from unittest.mock import patch
    config._offline_guards = [patch.object(socket.socket, "connect", _blocked),
                              patch.object(socket.socket, "connect_ex", _blocked),
                              patch.object(socket.socket, "sendto", _blocked),
                              patch.object(socket, "getaddrinfo", _blocked),
                              patch.object(subprocess, "Popen", _blocked)]
    for guard in config._offline_guards:
        guard.start()

def pytest_unconfigure(config):
    for guard in reversed(getattr(config, "_offline_guards", [])):
        guard.stop()
