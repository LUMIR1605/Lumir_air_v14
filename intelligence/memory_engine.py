from intelligence.history import load

def compare(current):
    """Compare current analysis with history"""
    if not current:
        return {"seen_before": False, "count": 0, "message": "Nowy temat."}
    
    history = load()
    
    topics = history.get("topics", {})
    topic = current.get("topic", "")
    
    return {
        "seen_before": topic in topics,
        "count": topics.get(topic, 0),
        "message": (
            f"Temat '{topic}' analizowano już {topics.get(topic, 0)} razy."
            if topic in topics
            else "Nowy temat."
        )
    }
