"""Information-gain based recommendations; this module never executes a pivot."""

import hashlib

from osint_lab.case_manifest import CaseManifest
from osint_lab.policies import SourceClass

from .models import EntityRef, EntityType, EvidenceItem, PivotCandidate, PivotStatus


class PivotPlanner:
    def plan(
        self,
        *,
        manifest: CaseManifest,
        evidence: tuple[EvidenceItem, ...],
        executed_collectors: tuple[str, ...],
        discovered_entities: tuple[EntityRef, ...] = (),
    ) -> tuple[PivotCandidate, ...]:
        pivots: list[PivotCandidate] = []
        seed_types = {seed.entity_type.upper() for seed in manifest.seed_entities}
        if "PHONE" in seed_types:
            seed = next(item for item in manifest.seed_entities if item.entity_type.upper() == "PHONE")
            allowed = SourceClass.PASSIVE_WEB in manifest.allowed_source_classes
            pivots.append(self._candidate(
                from_entity=EntityRef(entity_type=EntityType.PHONE, value_reference=seed.value),
                action="phone_public_web_search",
                proposed_input=seed.value,
                status=PivotStatus.RECOMMENDED if allowed else PivotStatus.BLOCKED,
                gain=0.75,
                cost=0.45,
                source=SourceClass.PASSIVE_WEB,
                reason=("Could add an independent public signal beyond local numbering metadata."
                        if allowed else "PASSIVE_WEB is not authorized by the case manifest."),
            ))
        discovered_email = next((item for item in discovered_entities if item.entity_type is EntityType.EMAIL), None)
        if "EMAIL" in seed_types or discovered_email is not None:
            seed_value = (
                next(item.value for item in manifest.seed_entities if item.entity_type.upper() == "EMAIL")
                if "EMAIL" in seed_types else discovered_email.value_reference
            )
            already = "email_local_metadata" in executed_collectors
            pivots.append(self._candidate(
                from_entity=EntityRef(entity_type=EntityType.EMAIL, value_reference=seed_value),
                action="email_local_metadata",
                proposed_input=seed_value,
                status=PivotStatus.LOW_VALUE if already else PivotStatus.RECOMMENDED,
                gain=0.12 if already else 0.65,
                cost=0.1,
                source=SourceClass.LOCAL,
                reason="The same local step already ran." if already else "Local parsing can expose a domain pivot safely.",
            ))
        if "DOMAIN" in seed_types:
            seed = next(item for item in manifest.seed_entities if item.entity_type.upper() == "DOMAIN")
            already = "domain_dns" in executed_collectors
            pivots.append(self._candidate(
                from_entity=EntityRef(entity_type=EntityType.DOMAIN, value_reference=seed.value),
                action="domain_dns",
                proposed_input=seed.value,
                status=PivotStatus.LOW_VALUE if already else PivotStatus.RECOMMENDED,
                gain=0.1 if already else 0.7,
                cost=0.25,
                source=SourceClass.PASSIVE_WEB,
                reason="Repeating the identical DNS step has low immediate information gain."
                       if already else "A point-in-time DNS observation may add technical context.",
            ))
        return tuple(sorted(pivots, key=lambda item: (-item.expected_information_gain, item.action)))

    @staticmethod
    def _candidate(*, from_entity: EntityRef, action: str, proposed_input: str, status: PivotStatus,
                   gain: float, cost: float, source: SourceClass, reason: str) -> PivotCandidate:
        digest = hashlib.sha256(f"{action}|{source.value}".encode()).hexdigest()[:16]
        return PivotCandidate(
            pivot_id=f"pivot-{digest}",
            from_entity=from_entity,
            proposed_collector=action,
            proposed_input=proposed_input,
            source_class=source.value,
            expected_information_gain=gain,
            privacy_cost=cost,
            network_cost=0.6 if source is not SourceClass.LOCAL else 0.0,
            duplication_risk=0.85 if status is PivotStatus.LOW_VALUE else 0.15,
            reason=reason,
            status=status,
        )
