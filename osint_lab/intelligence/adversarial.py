"""Deterministic challenge generation for analytical conclusions."""

import hashlib

from .models import AdversarialResult, AdversarialReview, CorrelationCandidate, Hypothesis


class AdversarialVerifier:
    def review_correlation(self, candidate: CorrelationCandidate) -> AdversarialReview:
        challenges: list[str] = []
        reasons: list[str] = []
        if candidate.left.entity_type.value == "USERNAME" or candidate.right.entity_type.value == "USERNAME":
            challenges.append("The same username can be used by unrelated people.")
        if len(candidate.supporting_sources) < 2:
            challenges.append("There is no second independent supporting observation.")
        if len(candidate.evidence_refs) > len(candidate.supporting_sources):
            challenges.append("Multiple observations belong to the same source-independence group.")
        if candidate.opposing_evidence:
            challenges.append("Recorded evidence directly opposes the proposed correlation.")
        if candidate.status.value == "REJECTED":
            result = AdversarialResult.REJECTED
            reasons.append("the correlation engine rejected the candidate")
        elif candidate.opposing_evidence:
            result = AdversarialResult.WEAKENED
            reasons.append("opposing evidence remains unresolved")
        elif challenges:
            result = AdversarialResult.INCONCLUSIVE
            reasons.append("plausible alternative explanations remain")
        else:
            result = AdversarialResult.SURVIVES
            reasons.append("no deterministic challenge was triggered")
        token = f"correlation|{candidate.correlation_id}"
        return AdversarialReview(
            review_id="adv-" + hashlib.sha256(token.encode()).hexdigest()[:16],
            hypothesis_id=candidate.correlation_id,
            counter_questions=("Could this correlation have a non-identity explanation?",),
            opposing_evidence_refs=candidate.opposing_sources,
            ambiguity_reasons=tuple(reasons),
            alternative_explanations=tuple(challenges) or ("No configured deterministic challenge.",),
            result=result,
        )

    def review_hypothesis(self, hypothesis: Hypothesis) -> AdversarialReview:
        challenges = list(hypothesis.alternative_explanations)
        if len(hypothesis.supporting_evidence) < 2:
            challenges.append("The hypothesis lacks two independent supporting observations.")
        if hypothesis.opposing_evidence:
            challenges.append("Recorded evidence opposes the hypothesis.")
        temporal_conflict = any("temporal" in reason or "contradictory" in reason for reason in hypothesis.reasons)
        if temporal_conflict:
            challenges.append("Conflicting values may reflect a temporal change or an incorrect association.")
        if hypothesis.status.value == "REJECTED":
            result = AdversarialResult.REJECTED
        elif hypothesis.opposing_evidence or temporal_conflict:
            result = AdversarialResult.WEAKENED
        elif challenges:
            result = AdversarialResult.INCONCLUSIVE
        else:
            result = AdversarialResult.SURVIVES
        return AdversarialReview(
            review_id="adv-" + hashlib.sha256(f"hypothesis|{hypothesis.hypothesis_id}".encode()).hexdigest()[:16],
            hypothesis_id=hypothesis.hypothesis_id,
            counter_questions=("What evidence would falsify this hypothesis?",),
            opposing_evidence_refs=hypothesis.evidence_against,
            ambiguity_reasons=("deterministic alternative-explanation review completed",),
            alternative_explanations=tuple(challenges) or ("No configured deterministic challenge.",),
            result=result,
        )
