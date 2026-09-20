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
        pending_links: list[tuple[EntityRef, EntityRef, str, str, str]] = []
        discovered_entities: list[EntityRef] = []
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
                canonical_url = self._first_text(payload, "profile_url", "endpoint_url", "url", "result_url")
                domain = self._domain(canonical_url) or self._first_text(
                    payload, "domain", "source_domain", "region_code"
                )
                content_hash = self._first_text(payload, "body_sha256", "content_hash")
                parent_ref = self._first_text(payload, "parent_source_ref", "source_reference")
                match_level = self._first_text(payload, "match_level")
                semantic_public_fact = (
                    payload.get("exact_match") is True
                    and match_level in {"PHONE_CONTEXT_MATCH", "STRUCTURED_PHONE_MATCH"}
                )
                raw_evidence.append(EvidenceItem(
                    evidence_id=evidence_id,
                    source_name=step.collector_name,
                    source_class=step.source_class.value,
                    collected_at=self._evidence_time(payload, result.finished_at),
                    reproducible=step.source_class is SourceClass.LOCAL or semantic_public_fact,
                    directness=(
                        Directness.DIRECT
                        if step.source_class is SourceClass.LOCAL or semantic_public_fact
                        else Directness.INDIRECT
                    ),
                    canonical_url=canonical_url,
                    domain=domain,
                    content_hash=content_hash,
                    payload_fingerprint=fingerprint,
                    parent_source_ref=parent_ref,
                    claim_key=f"{step.collector_name}:{step.seed_reference}:{observation.raw_status}",
                    claim_value=observation.raw_status,
                    match_level=match_level,
                ))
                known_facts.append(KnownFact(
                    statement=(f"Collector {step.collector_name} recorded technical status "
                               f"{observation.raw_status}; this is not an identity or ownership conclusion."),
                    evidence_refs=(evidence_id,),
                ))
                if step.seed_type.upper() == "USERNAME" and canonical_url and observation.raw_status == "CLAIMED":
                    pending_links.append((
                        EntityRef(entity_type=EntityType.USERNAME, value_reference=step.seed_reference),
                        EntityRef(entity_type=EntityType.SOCIAL_PROFILE, value_reference=canonical_url),
                        evidence_id,
                        "public_profile_candidate",
                        "exact_username",
                    ))
                if (
                    step.collector_name == "phone_public_web"
                    and observation.raw_status == "MATCH"
                    and semantic_public_fact
                ):
                    self._collect_phone_public_links(
                        payload=payload,
                        evidence_id=evidence_id,
                        pending_links=pending_links,
                        discovered_entities=discovered_entities,
                    )

        now = self._now()
        evidence, quality_summary = self._quality.assess(tuple(raw_evidence), now=now)
        evidence_by_id = {item.evidence_id: item for item in evidence}
        grouped_links: dict[tuple[EntityRef, EntityRef, str, str], list[str]] = {}
        for left, right, evidence_id, relation_type, match_kind in pending_links:
            grouped_links.setdefault((left, right, relation_type, match_kind), []).append(evidence_id)
        correlations = []
        for (left, right, relation_type, match_kind), evidence_ids in grouped_links.items():
            correlations.append(self._correlation.correlate(
                case_id=manifest.case_id,
                left=left,
                right=right,
                relation_type=relation_type,
                match_kind=match_kind,
                supporting=tuple(evidence_by_id[item] for item in dict.fromkeys(evidence_ids)),
            ))
        hypotheses = []
        for correlation in correlations:
            phone_public_relation = correlation.relation_type in {"MENTIONED_ON", "MENTIONS", "ASSOCIATED_WITH"}
            alternative = (
                "The public material may be stale, copied, or contextually unrelated to the current subscriber."
                if phone_public_relation
                else "The same username may be used by unrelated people."
            )
            unresolved_question = (
                "Can an independent current source corroborate this public occurrence and its context?"
                if phone_public_relation
                else "Can an independent source distinguish association from username coincidence?"
            )
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
                unresolved_questions=(unresolved_question,),
                alternative_explanations=(alternative,),
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
            discovered_entities=tuple(discovered_entities),
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

    @staticmethod
    def _evidence_time(payload: dict[str, object], fallback: datetime) -> datetime:
        source_date = payload.get("source_date")
        if not isinstance(source_date, str) or source_date == "UNKNOWN":
            return fallback
        try:
            value = datetime.fromisoformat(source_date.replace("Z", "+00:00"))
        except ValueError:
            return fallback
        return value if value.tzinfo is not None and value.utcoffset() is not None else fallback

    @staticmethod
    def _collect_phone_public_links(
        *,
        payload: dict[str, object],
        evidence_id: str,
        pending_links: list[tuple[EntityRef, EntityRef, str, str, str]],
        discovered_entities: list[EntityRef],
    ) -> None:
        phone = payload.get("canonical_phone")
        result_url = payload.get("result_url")
        if not isinstance(phone, str) or not isinstance(result_url, str):
            return
        phone_ref = EntityRef(entity_type=EntityType.PHONE, value_reference=phone)
        website_ref = EntityRef(entity_type=EntityType.WEBSITE, value_reference=result_url)
        pending_links.append((phone_ref, website_ref, evidence_id, "MENTIONED_ON", "exact_phone_public"))
        entities = payload.get("discovered_entities")
        if not isinstance(entities, list):
            return
        for item in entities:
            if not isinstance(item, dict):
                continue
            entity_type = item.get("entity_type")
            value = item.get("value")
            if not isinstance(entity_type, str) or not isinstance(value, str):
                continue
            try:
                ref = EntityRef(entity_type=EntityType(entity_type), value_reference=value)
            except ValueError:
                continue
            if ref not in discovered_entities:
                discovered_entities.append(ref)
            if ref.entity_type is EntityType.EMAIL:
                pending_links.append((website_ref, ref, evidence_id, "MENTIONS", "public_extraction"))
            elif ref.entity_type is EntityType.COMPANY:
                pending_links.append((phone_ref, ref, evidence_id, "ASSOCIATED_WITH", "public_extraction"))

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("intelligence clock must return a timezone-aware datetime")
        return value
