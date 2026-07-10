from shield.ai_advisor import advise
import json
from datetime import datetime

def build(result, outfile="shield_report.json"):
    report = {
        "generated": datetime.now().isoformat(),
        "engine": "Lumir SHIELD",
        "version": "0.2",
        "summary": {
            "scan_type": result.get("scan_type"),
            "risk": result.get("risk"),
            "score": result.get("risk_score", {}).get("score", 0)
        },
        "advice": advise(result),
        "result": result
    }

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return outfile
