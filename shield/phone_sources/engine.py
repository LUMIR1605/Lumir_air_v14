from .registry import SOURCES

def run(number):
    results = []

    for source in SOURCES:
        results.append({
            "name": source["name"],
            "status": "available" if source["enabled"] else "unavailable",
            "description": source["description"]
        })

    return results
