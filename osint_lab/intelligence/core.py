"""Post-collection deterministic intelligence pipeline."""

from datetime import datetime
import hashlib
import json
from typing import Callable, Iterable
from urllib.parse import urlsplit

from osint_lab.case_manifest import CaseManifest
from osint_lab.policies import SourceClass

from .adversarial import AdversarialVerifier
from .correlation import CorrelationEngine
from .models import (
    Directness,
    EntityRef,
    EntityType,
    EvidenceItem,
    Hypothesis,
    HypothesisStatus,
    IntelligenceSummary,
    KnownFact,
)
from .hypothesis import HypothesisEngine
from .pivot import PivotPlanner
from .quality import EvidenceQualityEngine


class IntelligenceCore:
    """Convert completed executions into conservative, explainable analytics."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime],
        quality_engine: EvidenceQualityEngine | None = None,
        correlation_engine: CorrelationEngine | None = None,
        adversarial_verifier: AdversarialVerifier | None = None,
        hypothesis_engine: HypothesisEngine | None = None,
        pivot_planner: PivotPlanner | None = None,
    ) -> None:
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._clock = clock
        self._quality = quality_engine or EvidenceQualityEngine()
        self._correlation = correlation_engine or CorrelationEngine()
        self._adversarial = adversarial_verifier or AdversarialVerifier()
        self._hypotheses = hypothesis_engine or HypothesisEngine()
        self._pivots = pivot_planner or PivotPlanner()

    def analyze(
        self,
        *,
        manifest: CaseManifest,
        executions: Iterable[object],
        contradiction: object,
    ) -> IntelligenceSummary:
        records = tuple(executions)
        raw_evidence: list[EvidenceItem] = []
        known_facts: list[KnownFact] = []
        username_links: list[tuple[EntityRef, EntityRef, str]] = []
        executed_collectors: list[str] = []

        for record in records:
            step = record.step
            result = record.result
            executed_collectors.append(step.collector_name)
            if result is None:
                continue
            for index, observation in enumerate(result.observations):
                payload = dict(observation.payload)
                fingerprint = hashlib.sha256(
                    json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                evidence_id = observation.evidence_ref or f"{result.execution_id}:observation:{index}"
                canonical_url = self._first_text(payload, "profile_url", "endpoint_url", "url")
                domain = self._domain(canonical_url) or self._first_text(payload, "domain", "region_code")
                content_hash = self._first_text(payload, "body_sha256", "content_hash")
                parent_ref = self._first_text(payload, "parent_source_ref", "source_reference")
                raw_evidence.append(EvidenceItem(
                    evidence_id=evidence_id,
                    source_name=step.collector_name,
                    source_class=step.source_class.value,
                    collected_at=result.finished_at,
                    reproducible=step.source_class is SourceClass.LOCAL,
                    directness=Directness.DIRECT if step.source_class is SourceClass.LOCAL else Directness.INDIRECT,
                    canonical_url=canonical_url,
                    domain=domain,
                    content_hash=content_hash,
                    payload_fingerprint=fingerprint,
                    parent_source_ref=parent_ref,
                    claim_key=f"{step.collector_name}:{step.seed_reference}:{observation.raw_status}",
                    claim_value=observation.raw_status,
                ))
                known_facts.append(KnownFact(
                    statement=(f"Collector {step.collector_name} recorded technical status "
                               f"{observation.raw_status}; this is not an identity or ownership conclusion."),
                    evidence_refs=(evidence_id,),
                ))
                if step.seed_type.upper() == "USERNAME" and canonical_url and observation.raw_status == "CLAIMED":
                    username_links.append((
                        EntityRef(entity_type=EntityType.USERNAME, value_reference=step.seed_reference),
                        EntityRef(entity_type=EntityType.SOCIAL_PROFILE, value_reference=canonical_url),
                        evidence_id,
                    ))

        now = self._now()
        evidence, quality_summary = self._quality.assess(tuple(raw_evidence), now=now)
        evidence_by_id = {item.evidence_id: item for item in evidence}
        correlations = []
        for left, right, evidence_id in username_links:
            correlations.append(self._correlation.correlate(
                case_id=manifest.case_id,
                left=left,
                right=right,
                relation_type="public_profile_candidate",
                match_kind="exact_username",
                supporting=(evidence_by_id[evidence_id],),
            ))
        hypotheses = []
        for correlation in correlations:
            draft = Hypothesis(
                hypothesis_id="hyp-" + correlation.correlation_id.removeprefix("corr-"),
                case_id=manifest.case_id,
                statement=(f"{correlation.left_entity.entity_type.value} {correlation.left_entity.value_reference} "
                           f"may be associated with {correlation.right_entity.entity_type.value} "
                           f"{correlation.right_entity.value_reference}."),
                subject_entities=(correlation.left_entity, correlation.right_entity),
                evidence_for=(),
                evidence_against=(),
                evidence_unknown=(),
                status=HypothesisStatus.OPEN,
                confidence=0.1,
                created_at=now,
                updated_at=now,
                reasons=("created from a non-confirmed correlation candidate",),
                unresolved_questions=("Can an independent source distinguish association from username coincidence?",),
                alternative_explanations=("The same username may be used by unrelated people.",),
            )
            hypotheses.append(self._hypotheses.assess(
                draft,
                supporting=tuple(evidence_by_id[item] for item in correlation.evidence_refs),
            ))
        reviews = tuple(self._adversarial.review_hypothesis(item) for item in hypotheses)
        pivots = self._pivots.plan(
            manifest=manifest,
            evidence=evidence,
            executed_collectors=tuple(executed_collectors),
        )
        contradiction_reasons = tuple(str(item) for item in getattr(contradiction, "reasons", ()))
        unresolved = ["Do independent sources corroborate any proposed correlation?"]
        if not correlations:
            unresolved.append("No entity correlation was established by the available technical observations.")
        return IntelligenceSummary(
            known_facts=tuple(known_facts),
            probable_correlations=tuple(correlations),
            open_hypotheses=tuple(hypotheses),
            contradictions=contradiction_reasons,
            evidence_quality=evidence,
            evidence_quality_summary=quality_summary,
            adversarial_reviews=reviews,
            recommended_pivots=pivots,
            unresolved_questions=tuple(unresolved),
        )

    @staticmethod
    def _first_text(payload: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _domain(url: str | None) -> str | None:
        return urlsplit(url).hostname.casefold() if url and urlsplit(url).hostname else None

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("intelligence clock must return a timezone-aware datetime")
        return value
