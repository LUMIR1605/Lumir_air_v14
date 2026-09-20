"""Project completed collector evidence and analytics into the persistent graph."""

from datetime import datetime
import hashlib
import ipaddress
import json
from typing import Iterable
from urllib.parse import urlsplit

from osint_lab.case_manifest import CaseManifest
from osint_lab.intelligence import IntelligenceSummary

from .models import (
    CaseEvent,
    CaseEventType,
    EntityNode,
    EntityRelation,
    GraphEntityType,
    GraphRelationType,
    GraphStatus,
    TimelineEvent,
    TimelineEventType,
)
from .normalization import EntityNormalizer
from .store import GraphStore, deterministic_entity_id, deterministic_relation_id


class GraphProjector:
    def __init__(self, *, normalizer: EntityNormalizer | None = None, source_registry=None) -> None:
        self.normalizer = normalizer or EntityNormalizer()
        self.source_registry = source_registry

    def project(
        self,
        *,
        store: GraphStore,
        manifest: CaseManifest,
        executions: Iterable[object],
        intelligence: IntelligenceSummary,
        run_id: str,
        started_at: datetime,
        finished_at: datetime,
    ) -> tuple[int, int]:
        graph_version_before = store.graph_version
        execution_values = tuple(executions)
        entities: dict[str, EntityNode] = {}
        timeline: list[TimelineEvent] = []
        events: list[CaseEvent] = []
        evidence_by_id = {item.evidence_id: item for item in intelligence.evidence_quality}

        for seed in manifest.seed_entities:
            try:
                entity_type = GraphEntityType(seed.entity_type.upper())
                normalized = self.normalizer.normalize(entity_type, seed.value)
            except (ValueError, KeyError):
                continue
            evidence_ref = "seed:" + hashlib.sha256(
                f"{manifest.case_id}|{entity_type.value}|{normalized.canonical_value}".encode()
            ).hexdigest()
            entity = self._entity(
                case_id=manifest.case_id, entity_type=entity_type, canonical=normalized.canonical_value,
                display=normalized.display_value, timestamp=manifest.created_at,
                source_refs=(f"manifest:{manifest.case_id}",), evidence_refs=(evidence_ref,),
                confidence=1.0, attributes={"seed": True, "hop": 0},
            )
            entities[entity.entity_id] = entity
            timeline.append(self._timeline(entity, evidence_ref, TimelineEventType.FIRST_SEEN, "case_manifest"))
            events.append(self._case_event(manifest.case_id, CaseEventType.SEED_ADDED, entity.entity_id,
                                           manifest.created_at, (evidence_ref,)))

        relations: list[EntityRelation] = []
        for record in execution_values:
            if record.result is None:
                continue
            for index, observation in enumerate(record.result.observations):
                payload = dict(observation.payload)
                evidence_id = observation.evidence_ref or f"{record.result.execution_id}:observation:{index}"
                evidence = evidence_by_id.get(evidence_id)
                group = evidence.independence_group if evidence is not None else f"execution:{record.result.execution_id}"
                timestamp = evidence.collected_at if evidence is not None else record.result.finished_at
                derived = self._derive_observation(record, observation)
                for left_type, left_value, right_type, right_value, relation_type, reason in derived:
                    try:
                        left = self._from_values(manifest.case_id, left_type, left_value, timestamp,
                                                 (evidence_id,), (record.step.collector_name,), hop=0)
                        right = self._from_values(manifest.case_id, right_type, right_value, timestamp,
                                                  (evidence_id,), (record.step.collector_name,), hop=1)
                    except ValueError:
                        continue
                    entities.setdefault(left.entity_id, left)
                    entities.setdefault(right.entity_id, right)
                    relation_id = deterministic_relation_id(manifest.case_id, left.entity_id, right.entity_id,
                                                            relation_type)
                    derived_relation = EntityRelation(
                        relation_id=relation_id, case_id=manifest.case_id, source_entity_id=left.entity_id,
                        target_entity_id=right.entity_id, relation_type=relation_type, first_seen=timestamp,
                        last_seen=timestamp, evidence_refs=(evidence_id,),
                        source_refs=(str(payload.get("source_id") or record.step.collector_name),),
                        independence_groups=(group,),
                        confidence=evidence.quality_score if evidence and evidence.quality_score is not None else 0.5,
                        status=GraphStatus.POSSIBLE, reasons=(reason,),
                        attributes={"collector": record.step.collector_name,
                                    "source_reputation": payload.get("source_reputation", "UNKNOWN"),
                                    "stale": bool(payload.get("temporal_evidence"))},
                    )
                    relations.append(derived_relation)
                    timeline.append(TimelineEvent(
                        event_id="time-" + hashlib.sha256(
                            f"relation|{relation_id}|{timestamp.isoformat()}".encode()
                        ).hexdigest()[:24],
                        case_id=manifest.case_id, entity_ids=(left.entity_id, right.entity_id),
                        relation_ids=(relation_id,), event_type=TimelineEventType.RELATION_APPEARED,
                        timestamp=timestamp, timestamp_source="collector_observation",
                        evidence_refs=(evidence_id,), confidence=derived_relation.confidence,
                        description=reason,
                    ))
                    events.append(self._case_event(manifest.case_id, CaseEventType.RELATION_CREATED,
                                                   relation_id, timestamp, (evidence_id,)))
                    if right.entity_id not in {item.subject_id for item in events
                                               if item.event_type is CaseEventType.ENTITY_DISCOVERED}:
                        events.append(self._case_event(
                            manifest.case_id, CaseEventType.ENTITY_DISCOVERED, right.entity_id,
                            timestamp, (evidence_id,), attributes={
                                "parent_entity": left.entity_id,
                                "source": str(payload.get("source_id") or record.step.collector_name),
                                "extraction_method": record.step.collector_name,
                                "confidence": derived_relation.confidence,
                            },
                        ))

        for correlation in intelligence.probable_correlations:
            left = self._from_ref(manifest.case_id, correlation.left_entity, finished_at,
                                  correlation.evidence_refs, correlation.supporting_sources)
            right = self._from_ref(manifest.case_id, correlation.right_entity, finished_at,
                                   correlation.evidence_refs, correlation.supporting_sources)
            if left is None or right is None or left.entity_id == right.entity_id:
                continue
            entities.setdefault(left.entity_id, left)
            entities.setdefault(right.entity_id, right)
            evidence = tuple(dict.fromkeys(correlation.evidence_refs))
            groups = tuple(dict.fromkeys(correlation.supporting_sources)) or ("UNASSESSED",)
            source_refs = tuple(sorted({evidence_by_id[item].source_name for item in evidence if item in evidence_by_id}))
            if not source_refs:
                source_refs = ("intelligence:correlation",)
            try:
                relation_type = GraphRelationType(correlation.relation_type)
            except ValueError:
                relation_type = GraphRelationType.OTHER
            status = GraphStatus(correlation.status.value)
            relation_id = deterministic_relation_id(manifest.case_id, left.entity_id, right.entity_id, relation_type)
            relation = EntityRelation(
                relation_id=relation_id, case_id=manifest.case_id, source_entity_id=left.entity_id,
                target_entity_id=right.entity_id, relation_type=relation_type, first_seen=finished_at,
                last_seen=finished_at, evidence_refs=evidence, source_refs=source_refs,
                independence_groups=groups, confidence=correlation.confidence, status=status,
                reasons=correlation.reasons, reviewer_decision_id=correlation.verification_decision_id,
                attributes={"correlation_id": correlation.correlation_id},
            )
            relations.append(relation)
            timeline.append(TimelineEvent(
                event_id="time-" + hashlib.sha256(f"relation|{relation_id}|{finished_at.isoformat()}".encode()).hexdigest()[:24],
                case_id=manifest.case_id, entity_ids=(left.entity_id, right.entity_id),
                relation_ids=(relation_id,), event_type=TimelineEventType.RELATION_APPEARED,
                timestamp=finished_at, timestamp_source="collector_evidence", evidence_refs=evidence,
                confidence=relation.confidence, description="Evidence-backed relation appeared.",
            ))
            events.append(self._case_event(manifest.case_id, CaseEventType.RELATION_CREATED, relation_id,
                                           finished_at, evidence))

        for evidence in intelligence.evidence_quality:
            store.record_evidence(
                evidence_id=evidence.evidence_id, source_ref=evidence.source_name,
                independence_group=evidence.independence_group, first_seen=evidence.collected_at,
                last_seen=evidence.collected_at, quality_score=evidence.quality_score,
            )
            events.append(self._case_event(manifest.case_id, CaseEventType.EVIDENCE_ADDED,
                                           evidence.evidence_id, evidence.collected_at, (evidence.evidence_id,)))
        store.add_batch(entities=entities.values(), relations=relations, timeline=timeline, events=events)
        collector_versions = {record.step.collector_name: record.collector_version for record in execution_values}
        provider_data = []
        for record in execution_values:
            if record.result is None:
                continue
            for observation in record.result.observations:
                payload = observation.payload
                provider_data.append({key: payload.get(key) for key in (
                    "provider_id", "reviewed_at", "collector_version", "terms_limitations_note"
                ) if payload.get(key) is not None})
        policy_payload = {
            "allowed_sources": sorted(item.value for item in manifest.allowed_source_classes),
            "forbidden_sources": sorted(item.value for item in manifest.forbidden_source_classes),
            "allowed_agents": sorted(manifest.allowed_agent_types),
        }
        store.record_run({
            "run_id": run_id, "graph_version_before": graph_version_before,
            "graph_version_after": store.graph_version + 1,
            "collector_versions": collector_versions,
            "provider_config_hash": hashlib.sha256(json.dumps(provider_data, sort_keys=True).encode()).hexdigest(),
            "policy_hash": hashlib.sha256(json.dumps(policy_payload, sort_keys=True).encode()).hexdigest(),
            "started_at": started_at.isoformat(), "finished_at": finished_at.isoformat(),
            "evidence_refs": sorted(evidence_by_id),
            "source_registry_version": getattr(self.source_registry, "version", None),
            "source_registry_config_hash": getattr(self.source_registry, "config_hash", None),
            "enabled_sources": [item.source_id for item in getattr(self.source_registry, "definitions", ())
                                if item.enabled],
            "source_parser_versions": {item.source_id: item.parser_version
                                       for item in getattr(self.source_registry, "definitions", ())},
        })
        return graph_version_before, store.graph_version

    def _from_ref(self, case_id, ref, timestamp, evidence_refs, source_refs):
        try:
            entity_type = GraphEntityType(ref.entity_type.value)
            normalized = self.normalizer.normalize(entity_type, ref.value_reference)
        except ValueError:
            return None
        return self._entity(case_id=case_id, entity_type=entity_type, canonical=normalized.canonical_value,
                            display=normalized.display_value, timestamp=timestamp,
                            source_refs=tuple(source_refs) or ("intelligence:correlation",),
                            evidence_refs=tuple(evidence_refs), confidence=0.7, attributes={"seed": False, "hop": 1})

    def _from_values(self, case_id, entity_type, value, timestamp, evidence_refs, source_refs, *, hop):
        normalized = self.normalizer.normalize(entity_type, value)
        return self._entity(case_id=case_id, entity_type=entity_type, canonical=normalized.canonical_value,
                            display=normalized.display_value, timestamp=timestamp, source_refs=source_refs,
                            evidence_refs=evidence_refs, confidence=0.7, attributes={"seed": hop == 0, "hop": hop})

    @staticmethod
    def _entity(*, case_id, entity_type, canonical, display, timestamp, source_refs, evidence_refs,
                confidence, attributes):
        return EntityNode(
            entity_id=deterministic_entity_id(case_id, entity_type, canonical), case_id=case_id,
            entity_type=entity_type, canonical_value=canonical, display_value=display,
            aliases=(display,), first_seen=timestamp, last_seen=timestamp, created_at=timestamp,
            updated_at=timestamp, source_refs=tuple(source_refs), evidence_refs=tuple(evidence_refs),
            confidence=confidence, status=GraphStatus.POSSIBLE, attributes=attributes,
        )

    @staticmethod
    def _timeline(entity, evidence_ref, event_type, timestamp_source):
        return TimelineEvent(
            event_id="time-" + hashlib.sha256(f"{entity.entity_id}|{event_type.value}|{entity.first_seen.isoformat()}".encode()).hexdigest()[:24],
            case_id=entity.case_id, entity_ids=(entity.entity_id,), relation_ids=(), event_type=event_type,
            timestamp=entity.first_seen, timestamp_source=timestamp_source, evidence_refs=(evidence_ref,),
            confidence=entity.confidence, description=f"{event_type.value} for {entity.entity_type.value}.",
        )

    @staticmethod
    def _case_event(case_id, event_type, subject_id, timestamp, evidence_refs, attributes=None):
        token = f"{event_type.value}|{subject_id}|{timestamp.isoformat()}"
        return CaseEvent(event_id="evt-" + hashlib.sha256(token.encode()).hexdigest()[:24], case_id=case_id,
                         event_type=event_type, timestamp=timestamp, subject_id=subject_id,
                         evidence_refs=tuple(evidence_refs), attributes=dict(attributes or {}))

    @staticmethod
    def _derive_observation(record, observation):
        payload = dict(observation.payload)
        name = record.step.collector_name
        seed = record.step.seed_reference
        values: list[tuple[GraphEntityType, str, GraphEntityType, str, GraphRelationType, str]] = []

        def add(left_type, left, right_type, right, relation, reason):
            if isinstance(right, str) and right.strip():
                values.append((left_type, left, right_type, right, relation, reason))

        if name == "email_local_metadata" and observation.raw_status == "VALID":
            add(GraphEntityType.EMAIL, seed, GraphEntityType.DOMAIN, payload.get("domain"),
                GraphRelationType.USES_DOMAIN, "validated email domain")
        elif name == "username_lookup" and observation.raw_status == "CLAIMED":
            add(GraphEntityType.USERNAME, seed, GraphEntityType.SOCIAL_PROFILE, payload.get("profile_url"),
                GraphRelationType.LINKS_TO, "provider-specific claimed profile signal")
        elif name == "domain_dns" and observation.raw_status == "FOUND":
            if payload.get("query_type") in {"A", "AAAA"} and isinstance(payload.get("records"), list):
                for candidate in payload["records"]:
                    try:
                        address = str(ipaddress.ip_address(str(candidate)))
                    except ValueError:
                        continue
                    add(GraphEntityType.DOMAIN, seed, GraphEntityType.IP, address,
                        GraphRelationType.HOSTED_ON, "point-in-time DNS address")
        elif name == "domain_rdap" and observation.raw_status == "FOUND":
            registrar = payload.get("registrar")
            add(GraphEntityType.DOMAIN, seed, GraphEntityType.COMPANY, registrar,
                GraphRelationType.REFERENCES, "RDAP registrar role; not domain ownership")
            for server in payload.get("nameservers", ()):
                add(GraphEntityType.DOMAIN, seed, GraphEntityType.DOMAIN, server,
                    GraphRelationType.LINKS_TO, "RDAP nameserver relationship")
        elif name == "email_public_web" and observation.raw_status in {
            "EXACT_EMAIL_MATCH", "STRUCTURED_EMAIL_MATCH", "OBFUSCATED_EMAIL_MATCH",
        }:
            add(GraphEntityType.EMAIL, seed, GraphEntityType.WEBSITE, payload.get("target_url"),
                GraphRelationType.MENTIONED_ON, "validated public email occurrence")
            add(GraphEntityType.EMAIL, seed, GraphEntityType.DOMAIN, payload.get("domain"),
                GraphRelationType.USES_DOMAIN, "email domain")
        elif name == "website_metadata" and observation.raw_status == "FOUND":
            website = str(payload.get("final_url") or seed)
            add(GraphEntityType.WEBSITE, website, GraphEntityType.DOMAIN,
                urlsplit(website).hostname, GraphRelationType.USES_DOMAIN, "website hostname")
            for item in payload.get("organizations", ()):
                if isinstance(item, dict):
                    add(GraphEntityType.WEBSITE, website, GraphEntityType.COMPANY, item.get("name"),
                        GraphRelationType.MENTIONS, "structured organization on public website")
            for item in payload.get("public_emails", ()):
                add(GraphEntityType.WEBSITE, website, GraphEntityType.EMAIL, item,
                    GraphRelationType.MENTIONS, "visible public email")
            for item in payload.get("public_phones", ()):
                add(GraphEntityType.WEBSITE, website, GraphEntityType.PHONE, item,
                    GraphRelationType.MENTIONS, "visible public phone")
        elif name == "company_public_web" and observation.raw_status == "STRUCTURED_COMPANY_MATCH":
            add(GraphEntityType.COMPANY, seed, GraphEntityType.WEBSITE, payload.get("target_url"),
                GraphRelationType.MENTIONED_ON, "exact structured company page")
            add(GraphEntityType.COMPANY, seed, GraphEntityType.DOMAIN, payload.get("domain"),
                GraphRelationType.USES_DOMAIN, "company page domain; not exclusive ownership")
            for item in payload.get("emails", ()):
                add(GraphEntityType.COMPANY, seed, GraphEntityType.EMAIL, item,
                    GraphRelationType.USES_EMAIL, "email published on matched company page")
            for item in payload.get("phones", ()):
                add(GraphEntityType.COMPANY, seed, GraphEntityType.PHONE, item,
                    GraphRelationType.USES_PHONE, "phone published on matched company page")
        elif name == "document_intelligence" and observation.raw_status == "FOUND":
            document = str(payload.get("document_url") or seed)
            for entity_type, key in ((GraphEntityType.EMAIL, "emails"), (GraphEntityType.PHONE, "phones"),
                                     (GraphEntityType.DOMAIN, "domains")):
                for item in payload.get(key, ()):
                    add(GraphEntityType.DOCUMENT, document, entity_type, item,
                        GraphRelationType.MENTIONS, "identifier extracted from bounded document text")
        elif name == "public_archive" and observation.raw_status == "FOUND":
            for item in payload.get("snapshots", ()):
                if isinstance(item, dict) and item.get("timestamp") and item.get("url"):
                    archive_ref = (f"https://data.commoncrawl.org/{item.get('filename')}"
                                   if item.get("filename") else f"https://index.commoncrawl.org/{item['timestamp']}")
                    add(GraphEntityType.WEBSITE, seed, GraphEntityType.DOCUMENT, archive_ref,
                        GraphRelationType.PUBLISHED_IN, "historical archive snapshot candidate")
        return values
