from datetime import datetime, timedelta, timezone

import pytest

from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.intelligence import (
    AdversarialResult,
    AdversarialVerifier,
    CorrelationCandidate,
    CorrelationEngine,
    CorrelationStatus,
    Directness,
    EntityRef,
    EntityType,
    EvidenceItem,
    EvidenceQualityEngine,
    Hypothesis,
    HypothesisEngine,
    HypothesisStatus,
    PivotPlanner,
    PivotStatus,
    ReviewerDecision,
    ReviewerDecisionEngine,
    ReviewerDecisionType,
    ReviewTargetType,
)
from osint_lab.policies import SourceClass


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)


def hypothesis(hypothesis_id: str = "hyp-1", statement: str = "A technical relationship may exist") -> Hypothesis:
    return Hypothesis(
        hypothesis_id=hypothesis_id,
        case_id="case",
        statement=statement,
        subject_entities=(),
        evidence_for=(),
        evidence_against=(),
        evidence_unknown=(),
        status=HypothesisStatus.OPEN,
        confidence=0.1,
        created_at=NOW,
        updated_at=NOW,
        reasons=(),
        unresolved_questions=("What independent evidence can test this?",),
    )


def evidence(
    evidence_id: str,
    *,
    source: str = "source-a",
    claim_key: str = "claim",
    claim_value: str = "yes",
    content_hash: str | None = None,
    payload_fingerprint: str | None = None,
    collected_at: datetime = NOW,
    directness: Directness = Directness.DIRECT,
) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=evidence_id,
        source_name=source,
        source_class="LOCAL",
        collected_at=collected_at,
        reproducible=True,
        directness=directness,
        content_hash=content_hash,
        payload_fingerprint=payload_fingerprint,
        claim_key=claim_key,
        claim_value=claim_value,
    )


def assessed(*values: EvidenceItem) -> tuple[EvidenceItem, ...]:
    return EvidenceQualityEngine().assess(tuple(values), now=NOW)[0]


def manifest(*, seed_type: str, passive: bool = False) -> CaseManifest:
    allowed = {SourceClass.LOCAL}
    if passive:
        allowed.add(SourceClass.PASSIVE_WEB)
    return CaseManifest(
        case_id="case-intelligence-001",
        case_name="Synthetic intelligence test",
        created_at=NOW,
        authorized_by="test-reviewer",
        purpose="Deterministic synthetic validation",
        legal_basis_or_consent_note="Synthetic fixtures only",
        seed_entities=(SeedEntity(entity_type=seed_type, value="fixture-value"),),
        allowed_source_classes=frozenset(allowed),
        forbidden_source_classes=frozenset({SourceClass.THIRD_PARTY_API, SourceClass.TOR, SourceClass.DIRECT_TARGET}),
        allowed_agent_types=frozenset({seed_type}),
        status=CaseStatus.ACTIVE,
    )


def test_duplicate_sources_do_not_raise_corroboration():
    items = assessed(
        evidence("ev-a", source="mirror-a", content_hash="same"),
        evidence("ev-b", source="mirror-b", content_hash="same"),
    )
    assert items[0].independence_group == items[1].independence_group
    assert items[0].corroboration_count == 0


def test_independent_sources_raise_quality_and_score_is_explained():
    one = assessed(evidence("ev-a", content_hash="a"))[0]
    two = assessed(evidence("ev-a", content_hash="a"), evidence("ev-b", content_hash="b"))
    assert two[0].corroboration_count == 1
    assert two[0].quality_score > one.quality_score
    assert any("independent" in reason for reason in two[0].reasons)


def test_stale_indirect_evidence_scores_lower():
    fresh, stale = assessed(
        evidence("fresh", content_hash="fresh"),
        evidence("stale", content_hash="stale", collected_at=NOW - timedelta(days=900),
                 directness=Directness.INFERENCE),
    )
    assert stale.quality_score < fresh.quality_score


def test_direct_evidence_scores_above_indirect_and_contradiction_lowers_score():
    direct = assessed(evidence("direct", content_hash="direct"))[0]
    indirect = assessed(evidence("indirect", content_hash="indirect", directness=Directness.INDIRECT))[0]
    contradicted = assessed(
        evidence("yes", content_hash="yes", claim_value="yes"),
        evidence("no", content_hash="no", claim_value="no"),
    )[0]
    assert direct.quality_score > indirect.quality_score
    assert contradicted.contradiction_count == 1
    assert contradicted.quality_score < direct.quality_score


def test_exact_email_is_stronger_than_exact_username():
    support = assessed(evidence("ev", content_hash="unique"))
    engine = CorrelationEngine()
    left = EntityRef(entity_type=EntityType.EMAIL, value_reference="fixture@example.invalid")
    right = EntityRef(entity_type=EntityType.DOMAIN, value_reference="example.invalid")
    email = engine.correlate(case_id="case", left=left, right=right, relation_type="contains_domain",
                             match_kind="exact_email", supporting=support)
    username = engine.correlate(case_id="case", left=left, right=right, relation_type="candidate",
                                match_kind="exact_username", supporting=support)
    assert email.confidence > username.confidence
    assert email.status is not CorrelationStatus.CONFIRMED


def test_contradictory_evidence_lowers_correlation_confidence():
    support = assessed(evidence("support", content_hash="s"))
    opposition = assessed(evidence("oppose", content_hash="o", claim_value="no"))
    engine = CorrelationEngine()
    left = EntityRef(entity_type=EntityType.EMAIL, value_reference="fixture@example.invalid")
    right = EntityRef(entity_type=EntityType.DOMAIN, value_reference="example.invalid")
    clean = engine.correlate(case_id="case", left=left, right=right, relation_type="candidate",
                             match_kind="exact_email", supporting=support)
    conflicted = engine.correlate(case_id="case", left=left, right=right, relation_type="candidate",
                                  match_kind="exact_email", supporting=support, opposing=opposition)
    assert conflicted.confidence < clean.confidence


def test_username_coincidence_generates_adversarial_alternative():
    candidate = CorrelationEngine().correlate(
        case_id="case",
        left=EntityRef(entity_type=EntityType.USERNAME, value_reference="fixture_name"),
        right=EntityRef(entity_type=EntityType.SOCIAL_PROFILE, value_reference="https://example.invalid/u/fixture"),
        relation_type="public_profile_candidate",
        match_kind="exact_username",
        supporting=assessed(evidence("ev", content_hash="one")),
    )
    review = AdversarialVerifier().review_correlation(candidate)
    assert review.result is AdversarialResult.INCONCLUSIVE
    assert any("unrelated" in item for item in review.challenges)


def test_adversarial_review_detects_duplicate_source_group():
    copies = assessed(
        evidence("copy-a", content_hash="same"),
        evidence("copy-b", content_hash="same"),
    )
    candidate = CorrelationEngine().correlate(
        case_id="case",
        left=EntityRef(entity_type=EntityType.USERNAME, value_reference="fixture_name"),
        right=EntityRef(entity_type=EntityType.SOCIAL_PROFILE, value_reference="https://example.invalid/u/fixture"),
        relation_type="public_profile_candidate",
        match_kind="exact_username",
        supporting=copies,
    )
    review = AdversarialVerifier().review_correlation(candidate)
    assert review.result is AdversarialResult.INCONCLUSIVE
    assert any("same source-independence" in item for item in review.challenges)


def test_temporal_conflict_weakens_hypothesis():
    value = hypothesis(statement="The technical endpoint may have changed over time")
    support = assessed(evidence("old", content_hash="old", claim_value="a"))
    opposition = assessed(evidence("new", content_hash="new", claim_value="b"))
    result = HypothesisEngine().assess(value, supporting=support, opposing=opposition)
    assert result.status in {HypothesisStatus.WEAKENED, HypothesisStatus.REJECTED}
    assert result.status is not HypothesisStatus.VERIFIED


def test_conflicting_timeline_inside_support_is_detected():
    conflicting = assessed(
        evidence("older", content_hash="old", claim_value="old-value", collected_at=NOW - timedelta(days=400)),
        evidence("newer", content_hash="new", claim_value="new-value"),
    )
    result = HypothesisEngine().assess(hypothesis(), supporting=conflicting)
    assert result.status is HypothesisStatus.WEAKENED
    assert any("temporal" in reason for reason in result.reasons)


def test_more_independent_evidence_raises_hypothesis_support():
    engine = HypothesisEngine()
    one = engine.assess(hypothesis(), supporting=assessed(evidence("one", content_hash="one")))
    two = engine.assess(
        hypothesis(),
        supporting=assessed(evidence("one", content_hash="one"), evidence("two", content_hash="two")),
    )
    assert two.confidence > one.confidence


def test_unsupported_hypothesis_stays_open():
    result = HypothesisEngine().assess(
        hypothesis("hyp-2", "A further technical relationship may exist"),
        supporting=(),
    )
    assert result.status is HypothesisStatus.OPEN


def test_hypothesis_cannot_claim_owner_without_review():
    with pytest.raises(ValueError, match="ownership"):
        HypothesisEngine().assess(
            hypothesis("hyp-3", "This account is the owner of the number"),
            supporting=(),
        )


def test_verified_and_confirmed_require_reviewer_decision():
    with pytest.raises(ValueError, match="reviewer"):
        Hypothesis(**{**hypothesis("hyp", "Synthetic technical hypothesis").__dict__,
                      "status": HypothesisStatus.VERIFIED, "confidence": 1.0})
    with pytest.raises(ValueError, match="reviewer"):
        CorrelationCandidate(
            correlation_id="corr", case_id="case",
            left_entity=EntityRef(entity_type=EntityType.EMAIL, value_reference="a@example.invalid"),
            right_entity=EntityRef(entity_type=EntityType.DOMAIN, value_reference="example.invalid"),
            relation_type="contains_domain", evidence_refs=(), supporting_sources=(), opposing_sources=(),
            reasons=(), status=CorrelationStatus.CONFIRMED, confidence=1.0,
        )


def test_reviewer_decision_promotes_only_the_targeted_hypothesis():
    value = Hypothesis(**{**hypothesis("hyp", "Synthetic technical hypothesis").__dict__,
                         "status": HypothesisStatus.SUPPORTED, "confidence": 0.8})
    decision = ReviewerDecision(decision_id="decision-1", target_type=ReviewTargetType.HYPOTHESIS,
                                target_id="hyp", decision=ReviewerDecisionType.CONFIRM,
                                reviewer="reviewer", timestamp=NOW, notes="Reviewed fixture evidence",
                                evidence_refs=("fixture-evidence",))
    result = ReviewerDecisionEngine().apply_hypothesis(value, decision)
    assert result.status is HypothesisStatus.VERIFIED
    assert result.verification_decision_id == "decision-1"


def test_reviewer_decision_promotes_correlation_to_confirmed():
    candidate = CorrelationEngine().correlate(
        case_id="case",
        left=EntityRef(entity_type=EntityType.EMAIL, value_reference="a@example.invalid"),
        right=EntityRef(entity_type=EntityType.DOMAIN, value_reference="example.invalid"),
        relation_type="contains_domain",
        match_kind="exact_email",
        supporting=assessed(evidence("one", content_hash="one"), evidence("two", content_hash="two")),
    )
    decision = ReviewerDecision(
        decision_id="decision-correlation",
        target_type=ReviewTargetType.CORRELATION,
        target_id=candidate.correlation_id,
        decision=ReviewerDecisionType.CONFIRM,
        reviewer="reviewer",
        timestamp=NOW,
        notes="Synthetic review",
        evidence_refs=candidate.evidence_refs,
    )
    confirmed = ReviewerDecisionEngine().apply_correlation(candidate, decision)
    assert confirmed.status is CorrelationStatus.CONFIRMED
    assert confirmed.verification_decision_id == decision.decision_id


def test_phone_metadata_only_recommends_or_blocks_public_pivot():
    planner = PivotPlanner()
    allowed = planner.plan(manifest=manifest(seed_type="PHONE", passive=True), evidence=(),
                           executed_collectors=("phone_metadata",))
    blocked = planner.plan(manifest=manifest(seed_type="PHONE", passive=False), evidence=(),
                           executed_collectors=("phone_metadata",))
    assert allowed[0].status is PivotStatus.RECOMMENDED
    assert blocked[0].status is PivotStatus.BLOCKED
    assert 0 <= allowed[0].cost <= 1
    assert 0 <= allowed[0].privacy_cost <= 1
    assert 0 <= allowed[0].network_cost <= 1


def test_repeated_identical_step_is_low_value():
    pivots = PivotPlanner().plan(manifest=manifest(seed_type="DOMAIN", passive=True), evidence=(),
                                 executed_collectors=("domain_dns",))
    assert pivots[0].status is PivotStatus.LOW_VALUE


def test_new_email_pivot_is_recommended_and_planner_does_not_execute():
    pivots = PivotPlanner().plan(manifest=manifest(seed_type="EMAIL"), evidence=(), executed_collectors=())
    assert pivots[0].action == "email_local_metadata"
    assert pivots[0].status is PivotStatus.RECOMMENDED


def test_discovered_email_produces_email_pivot():
    pivots = PivotPlanner().plan(
        manifest=manifest(seed_type="USERNAME"),
        evidence=(),
        executed_collectors=(),
        discovered_entities=(EntityRef(entity_type=EntityType.EMAIL, value_reference="fixture@example.invalid"),),
    )
    assert pivots[0].proposed_collector == "email_local_metadata"
    assert pivots[0].status is PivotStatus.RECOMMENDED
