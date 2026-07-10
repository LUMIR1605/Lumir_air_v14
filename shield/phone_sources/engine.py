from .registry import SOURCES

def run(number):
    results = []

    for source in SOURCES:
        if source["enabled"]:
            results.append({
                "name": source["name"],
                "status": "enabled",
                "description": source["description"]
            })

    return results
