import json

from shield.truth import validate_report


def build(result, outfile="shield_report.json"):
    """Validate and persist the engine result; this JSON is the presentation source of truth."""
    validate_report(result)
    with open(outfile, "w", encoding="utf-8") as report_file:
        json.dump(result, report_file, indent=2, ensure_ascii=False)
    return outfile
