"""Conservative ACCOUNT_AUDIT projection into the private case graph."""

from datetime import datetime
import hashlib

from osint_lab.graph import (
    EntityNode,
    EntityRelation,
    GraphEntityType,
    GraphRelationType,
    GraphStatus,
    GraphStore,
    deterministic_entity_id,
    deterministic_relation_id,
)

from .models import AccountAuditResult, AccountAuditStatus


def project_account_audit(
    *,
    store: GraphStore,
    case_id: str,
    email_hash: str,
    results: tuple[AccountAuditResult, ...],
    timestamp: datetime,
) -> int:
    """Add only POSSIBLE_ACCOUNT_AT edges for FOUND signals; never identity."""

    found = tuple(item for item in results if item.status is AccountAuditStatus.FOUND)
    if not found:
        return 0
    email_ref = f"account-audit-email:{email_hash}"
    email_id = deterministic_entity_id(case_id, GraphEntityType.EMAIL, email_hash)
    email = EntityNode(
        entity_id=email_id,
        case_id=case_id,
        entity_type=GraphEntityType.EMAIL,
        canonical_value=email_hash,
        display_value=f"email-sha256:{email_hash[:12]}",
        aliases=(),
        first_seen=timestamp,
        last_seen=timestamp,
        created_at=timestamp,
        updated_at=timestamp,
        source_refs=("account_audit",),
        evidence_refs=(email_ref,),
        confidence=1.0,
        status=GraphStatus.POSSIBLE,
        attributes={"value_kind": "SHA256", "mode": "ACCOUNT_AUDIT"},
    )
    entities = [email]
    relations = []
    for item in found:
        service_id = deterministic_entity_id(case_id, GraphEntityType.SERVICE, item.domain)
        evidence = "account-audit-result:" + hashlib.sha256(
            f"{case_id}|{item.service_id}|{item.checked_at.isoformat()}".encode("utf-8")
        ).hexdigest()
        entities.append(EntityNode(
            entity_id=service_id,
            case_id=case_id,
            entity_type=GraphEntityType.SERVICE,
            canonical_value=item.domain,
            display_value=item.service_name,
            aliases=(),
            first_seen=timestamp,
            last_seen=timestamp,
            created_at=timestamp,
            updated_at=timestamp,
            source_refs=(item.source_adapter,),
            evidence_refs=(evidence,),
            confidence=0.75 if item.confidence.value == "HIGH" else 0.55,
            status=GraphStatus.POSSIBLE,
            attributes={"mode": "ACCOUNT_AUDIT", "provider_version": item.provider_version},
        ))
        relation_id = deterministic_relation_id(
            case_id, email_id, service_id, GraphRelationType.POSSIBLE_ACCOUNT_AT
        )
        relations.append(EntityRelation(
            relation_id=relation_id,
            case_id=case_id,
            source_entity_id=email_id,
            target_entity_id=service_id,
            relation_type=GraphRelationType.POSSIBLE_ACCOUNT_AT,
            first_seen=timestamp,
            last_seen=timestamp,
            evidence_refs=(evidence,),
            source_refs=(item.source_adapter,),
            independence_groups=(item.source_adapter,),
            confidence=0.75 if item.confidence.value == "HIGH" else 0.55,
            status=GraphStatus.POSSIBLE,
            reasons=("Account-audit provider signal; not ownership or identity confirmation.",),
            attributes={"mode": "ACCOUNT_AUDIT", "detection_method": item.detection_method.value},
        ))
    store.add_batch(entities=entities, relations=relations)
    return len(relations)
