"""Truthfulness contract for Lumir SHIELD engine data."""

from datetime import datetime, timezone
from pathlib import Path
import json
import uuid


SCHEMA_VERSION = "3.0"
FORMULA_VERSION = "3.0"
VALID_STATUSES = {"completed", "partial", "unavailable", "blocked", "timeout", "error", "not_applicable"}
PROFILES = {
    "email": {"email_scan": 30, "breach_scan": 35, "account_exposure_scan": 15, "domain_scan": 20},
    "domain": {"domain_scan": 30, "dns_scan": 25, "mail_security_scan": 20, "web_security_scan": 25},
    "username": {"username_scan": 100},
    "url": {"url_scan": 60, "domain_scan": 20, "web_security_scan": 20},
    "phone": {"phone_scan": 100},
}
CONTROL_STATUSES = {"passed", "failed", "unknown", "error", "not_applicable", "not_checked"}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def mask_email(value):
    if "@" not in value:
        return value
    local, domain = value.split("@", 1)
    return f"{local[:2]}***@{domain}"


def load_sources():
    path = Path(__file__).resolve().parents[1] / "config" / "shield_sources.json"
    return {item["source_id"]: item for item in json.loads(path.read_text(encoding="utf-8"))["sources"]}


def source_record(source_id, status, *, duration_ms=0, evidence=None, confidence=None, error_reason=None, request_log_ref=None, data_freshness=None):
    source = load_sources().get(source_id, {"source_id": source_id, "source_name": source_id, "tos_review_status": "rejected"})
    if source.get("tos_review_status") != "approved":
        status, confidence = "blocked", None
        error_reason = error_reason or "source is not approved by the project allowlist"
    if status not in {"completed", "partial"}:
        confidence = None
    return {
        "source_id": source["source_id"], "source_name": source["source_name"], "status": status,
        "checked_at": now_iso(), "duration_ms": duration_ms, "evidence": evidence or {},
        "confidence": confidence, "error_reason": error_reason, "request_log_ref": request_log_ref,
        "data_freshness": data_freshness, "terms_status": source.get("tos_review_status", "rejected"),
    }


def module_placeholder(name, status, reason, weight):
    return {
        "module": name, "scan_status": status, "risk": "unknown", "score": None,
        "confidence": None, "findings": [], "error_reason": reason, "original_weight": weight,
        "sources": [], "applicable": status != "not_applicable",
    }


def normalize_module(module, weight):
    status = module.get("scan_status", "completed")
    if status not in VALID_STATUSES:
        status = "error"
    module["scan_status"] = status
    module["original_weight"] = weight
    module["applicable"] = status != "not_applicable"
    module["sources"] = module.get("sources", [])
    if status == "completed":
        score = module.get("score")
        if not isinstance(score, (int, float)):
            module["scan_status"] = "partial"
            module["score"] = None
            module["risk"] = "unknown"
            module["confidence"] = None
            return module
        module["score"] = round(score)
        module["risk"] = "low" if score >= 90 else "medium" if score >= 70 else "high" if score >= 40 else "critical"
        module["confidence"] = module.get("confidence", 0.7) if isinstance(module.get("confidence", 0.7), (float, int)) else 0.7
    else:
        module["score"] = None
        module["confidence"] = None
        if status == "unavailable" and module.get("risk") == "low":
            module["risk"] = "unknown"
    return module


def assessment(modules, scan_type):
    applicable = [item for item in modules if item.get("applicable", True)]
    completed = [item for item in applicable if item.get("scan_status") == "completed" and item.get("score") is not None]
    denominator = sum(item.get("original_weight", 0) for item in applicable)
    completed_weight = sum(item.get("original_weight", 0) for item in completed)
    coverage = round((completed_weight / denominator * 100) if denominator else 0, 2)
    normalized = {item["module"]: round(item["original_weight"] / completed_weight * 100, 4) for item in completed} if completed_weight else {}
    components = {item["module"]: {"score": item["score"], "original_weight": item["original_weight"], "normalized_weight": normalized[item["module"]]} for item in completed}
    score = round(sum(item["score"] * normalized[item["module"]] / 100 for item in completed)) if completed else None
    rating = "low" if score is not None and score >= 90 else "medium" if score is not None and score >= 70 else "high" if score is not None and score >= 40 else "critical" if score is not None else None
    controls = [check for item in applicable for check in item.get("score_basis", []) if check.get("status") != "not_applicable"]
    resolved_controls = [check for check in controls if check.get("status") in {"passed", "failed"}]
    control_coverage = round((sum(check.get("weight", 0) for check in resolved_controls) / sum(check.get("weight", 0) for check in controls) * 100) if controls and sum(check.get("weight", 0) for check in controls) else 0, 2)
    reliability = "high" if coverage >= 80 and control_coverage >= 80 else "medium" if coverage >= 50 and control_coverage >= 50 else "insufficient"
    verdict = f"Wynik {score}/100 dotyczy {coverage}% wazonego zakresu modulow i {control_coverage}% kontroli." if reliability != "insufficient" and score is not None else "Pokrycie analizy jest zbyt niskie, aby wystawic pelna ocene bezpieczenstwa."
    return {
        "security_assessment": {"score": score, "rating": rating, "public_verdict": verdict, "calculation_details": {"formula_version": FORMULA_VERSION, "completed_modules": [item["module"] for item in completed], "excluded_modules": [item["module"] for item in applicable if item not in completed], "original_weights": {item["module"]: item.get("original_weight", 0) for item in applicable}, "normalized_weights": normalized, "weighted_components": components}},
        "assessment_reliability": reliability,
        "coverage": {"module_weighted_percent": coverage, "control_weighted_percent": control_coverage, "weighted_percent": coverage, "completed_modules": [item["module"] for item in completed], "partial_modules": [item["module"] for item in applicable if item.get("scan_status") == "partial"], "failed_modules": [item["module"] for item in applicable if item.get("scan_status") in {"error", "timeout"}], "unavailable_modules": [item["module"] for item in applicable if item.get("scan_status") == "unavailable"], "blocked_modules": [item["module"] for item in applicable if item.get("scan_status") == "blocked"], "applicable_planned_count": len(applicable), "completed_count": len(completed), "not_applicable_count": len([item for item in modules if not item.get("applicable", True)]), "resolved_controls": len(resolved_controls), "planned_controls": len(controls), "numeric_text": f"module {coverage}%, kontrole {control_coverage}%", "missing_modules": [item["module"] for item in applicable if item not in completed]},
    }


def base_report(scan_type, target, consent_declared=False):
    return {"schema_version": SCHEMA_VERSION, "engine_version": "0.6.0", "formula_version": FORMULA_VERSION, "scan_id": str(uuid.uuid4()), "generated_at": now_iso(), "scan_mode": "local_only", "scan_type": scan_type, "target": target, "consent": {"declared": consent_declared, "scope": "user declares ownership or authorization" if consent_declared else None, "recorded_at": now_iso() if consent_declared else None}, "request_log": [], "services": {"planned_count": 0, "attempted_count": 0, "checked_count": 0, "confirmed_count": 0, "probable_count": 0, "not_found_count": 0, "not_checked_count": 0, "results": []}, "requests": {"attempted_count": 0, "completed_count": 0, "failed_count": 0, "log_entries": []}}


def validate_report(report):
    required = {"schema_version", "engine_version", "formula_version", "scan_id", "generated_at", "scan_mode", "consent", "modules", "security_assessment", "coverage", "assessment_reliability"}
    missing = required - set(report)
    if missing or report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"invalid report schema: missing={sorted(missing)}")
    for module in report["modules"]:
        status = module.get("scan_status")
        if status not in VALID_STATUSES or (status != "completed" and module.get("score") is not None):
            raise ValueError(f"invalid module state: {module.get('module')}")
        if status == "completed" and (not isinstance(module.get("score"), (int, float)) or not 0 <= module["score"] <= 100 or not module.get("score_basis")):
            raise ValueError(f"completed module without valid evidence score: {module.get('module')}")
        for check in module.get("score_basis", []):
            if check.get("status") not in CONTROL_STATUSES or (check.get("points_awarded") is not None and check.get("points_awarded") > check.get("weight", 0)):
                raise ValueError(f"invalid control: {check.get('check_id')}")
        if status != "completed" and module.get("confidence") is not None:
            raise ValueError(f"invalid module confidence: {module.get('module')}")
    return True
