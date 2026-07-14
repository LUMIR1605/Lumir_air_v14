from shield.breach_scan import scan as breach_scan
from shield.truth import assessment, module_placeholder, normalize_module, validate_report


def test_hibp_without_key_is_unavailable(monkeypatch):
    monkeypatch.delenv("LUMIR_HIBP_API_KEY", raising=False)
    result = breach_scan("test@example.com")
    assert result["scan_status"] == "unavailable"
    assert result["score"] is None and result["breaches"] is None


def test_coverage_excludes_partial_and_not_applicable():
    completed = normalize_module({
        "module": "ok",
        "scan_status": "completed",
        "score": 100,
        "risk": "low",
        "score_basis": [{
            "check_id": "fixture_check",
            "status": "passed",
            "weight": 100,
            "points_awarded": 100,
            "evidence": {},
        }],
    }, 50)
    partial = normalize_module({"module": "partial", "scan_status": "partial", "risk": "high"}, 30)
    skipped = module_placeholder("skip", "not_applicable", "fixture", 20)
    result = assessment([completed, partial, skipped], "email")
    assert result["coverage"]["weighted_percent"] == 62.5
    assert result["security_assessment"]["score"] == 100


def test_invalid_non_completed_score_is_rejected():
    report = {"schema_version": "3.0", "engine_version": "x", "formula_version": "3.0", "scan_id": "x", "generated_at": "x", "scan_mode": "mocked", "consent": {}, "modules": [{"module": "bad", "scan_status": "unavailable", "score": 100, "confidence": None}], "security_assessment": {}, "coverage": {}, "assessment_reliability": "insufficient"}
    try:
        validate_report(report)
    except ValueError:
        return
    assert False, "schema accepted a score for an unavailable module"
