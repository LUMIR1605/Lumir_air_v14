from intelligence.history import load, save


def discover(result: dict):
    """
    Główna funkcja odpowiedzialna za uczenie się Lumíra.
    """

    history = load()

    history.setdefault("discoveries", [])
    history.setdefault("topics", {})
    history.setdefault("hypotheses", [])

    topic = result.get("topic", "").strip()

    if topic:
        history["topics"][topic] = history["topics"].get(topic, 0) + 1

    discovery = {
        "topic": topic,
        "trend": result.get("trend", ""),
        "opportunity": result.get("opportunity", ""),
        "business": result.get("business", ""),
        "video": result.get("video", ""),
        "ebook": result.get("ebook", "")
    }

    if discovery not in history["discoveries"]:
        history["discoveries"].append(discovery)

    if history["topics"].get(topic, 0) >= 3:

        hypothesis = (
            f"Temat '{topic}' pojawił się "
            f"{history['topics'][topic]} razy. "
            "Może oznaczać długoterminowy trend."
        )

        if hypothesis not in history["hypotheses"]:
            history["hypotheses"].append(hypothesis)

    save(history)

    return history
