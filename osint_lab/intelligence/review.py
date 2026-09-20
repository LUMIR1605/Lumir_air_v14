"""Only explicit reviewer decisions may promote analytical conclusions."""

from .models import (
    CorrelationCandidate,
    CorrelationStatus,
    Hypothesis,
    HypothesisStatus,
    ReviewerDecision,
    ReviewerDecisionType,
    ReviewTargetType,
    replace_correlation,
    replace_hypothesis,
)


class ReviewerDecisionEngine:
    def apply_correlation(self, value: CorrelationCandidate, decision: ReviewerDecision) -> CorrelationCandidate:
        if decision.target_type is not ReviewTargetType.CORRELATION or decision.target_id != value.correlation_id:
            raise ValueError("reviewer decision does not target this correlation")
        if decision.decision is ReviewerDecisionType.CONFIRM:
            return replace_correlation(value, status=CorrelationStatus.CONFIRMED,
                                       verification_decision_id=decision.decision_id)
        if decision.decision is ReviewerDecisionType.REJECT:
            return replace_correlation(value, status=CorrelationStatus.REJECTED,
                                       verification_decision_id=decision.decision_id)
        return replace_correlation(value, status=CorrelationStatus.POSSIBLE,
                                   verification_decision_id=decision.decision_id)

    def apply_hypothesis(self, value: Hypothesis, decision: ReviewerDecision) -> Hypothesis:
        if decision.target_type is not ReviewTargetType.HYPOTHESIS or decision.target_id != value.hypothesis_id:
            raise ValueError("reviewer decision does not target this hypothesis")
        if decision.decision is ReviewerDecisionType.CONFIRM:
            return replace_hypothesis(value, status=HypothesisStatus.VERIFIED,
                                      verification_decision_id=decision.decision_id)
        if decision.decision is ReviewerDecisionType.REJECT:
            return replace_hypothesis(value, status=HypothesisStatus.REJECTED,
                                      verification_decision_id=decision.decision_id)
        return replace_hypothesis(value, status=HypothesisStatus.OPEN,
                                  verification_decision_id=decision.decision_id)
