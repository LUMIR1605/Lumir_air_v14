SOURCES = {
    "beatport": {
        "enabled": True,
        "priority": 1,
        "type": "electronic"
    },
    "youtube": {
        "enabled": True,
        "priority": 2,
        "type": "general"
    },
    "spotify": {
        "enabled": True,
        "priority": 3,
        "type": "general"
    }
}

def enabled_sources():
    return [name for name, cfg in SOURCES.items() if cfg["enabled"]]
