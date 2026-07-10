def calculate(results):
    if isinstance(results, dict):
        results = [results]

    score = 100
    findings = 0

    for r in results:
        findings += len(r.get("findings", []))

        risk = str(r.get("risk", "low")).lower()

        if risk == "critical":
            score -= 50
        elif risk == "high":
            score -= 30
        elif risk == "medium":
            score -= 15
        elif risk == "low":
            score -= 2

    score -= findings * 5

    score = max(0, min(score, 100))

    if score >= 90:
        level = "LOW"
    elif score >= 70:
        level = "MEDIUM"
    elif score >= 40:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "score": score,
        "risk": level
    }
