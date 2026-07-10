from .roadmap import PHONE_SOURCES

def progress():
    total = len(PHONE_SOURCES)
    done = sum(1 for s in PHONE_SOURCES if s["status"] == "DONE")

    return {
        "done": done,
        "total": total,
        "percent": round(done / total * 100)
    }
