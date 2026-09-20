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
        passive_allowed = SourceClass.PASSIVE_WEB in manifest.allowed_source_classes
        if "PHONE" in seed_types:
            seed = next(item for item in manifest.seed_entities if item.entity_type.upper() == "PHONE")
            already = "phone_public_web" in executed_collectors
            status = (
                PivotStatus.BLOCKED if not passive_allowed
                else PivotStatus.LOW_VALUE if already
                else PivotStatus.RECOMMENDED
            )
            pivots.append(self._candidate(
                from_entity=EntityRef(entity_type=EntityType.PHONE, value_reference=seed.value),
                action="phone_public_web_search",
                proposed_input=seed.value,
                status=status,
                gain=0.12 if already else 0.75,
                cost=0.45,
                source=SourceClass.PASSIVE_WEB,
                reason=(
                    "PASSIVE_WEB is not authorized by the case manifest."
                    if not passive_allowed
                    else "The identical phone public-web step already ran."
                    if already
                    else "Could add an independent public signal beyond local numbering metadata."
                ),
            ))
        email_values = {
            item.value for item in manifest.seed_entities if item.entity_type.upper() == "EMAIL"
        } | {
            item.value_reference for item in discovered_entities if item.entity_type is EntityType.EMAIL
        }
        for seed_value in sorted(email_values):
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
            exposure_already = "email_exposure" in executed_collectors
            exposure_status = (
                PivotStatus.BLOCKED if not passive_allowed
                else PivotStatus.LOW_VALUE if exposure_already
                else PivotStatus.RECOMMENDED
            )
            pivots.append(self._candidate(
                from_entity=EntityRef(entity_type=EntityType.EMAIL, value_reference=seed_value),
                action="email_exposure",
                proposed_input=seed_value,
                status=exposure_status,
                gain=0.1 if exposure_already else 0.6,
                cost=0.5,
                source=SourceClass.PASSIVE_WEB,
                reason=(
                    "PASSIVE_WEB is not authorized by the case manifest."
                    if not passive_allowed
                    else "The same public exposure step already ran."
                    if exposure_already
                    else "A discovered public email can be checked by the reviewed exposure collector."
                ),
            ))
        domain_values = {
            item.value for item in manifest.seed_entities if item.entity_type.upper() == "DOMAIN"
        } | {
            item.value_reference for item in discovered_entities if item.entity_type is EntityType.DOMAIN
        }
        for domain_value in sorted(domain_values):
            already = "domain_dns" in executed_collectors
            status = (
                PivotStatus.BLOCKED if not passive_allowed
                else PivotStatus.LOW_VALUE if already
                else PivotStatus.RECOMMENDED
            )
            pivots.append(self._candidate(
                from_entity=EntityRef(entity_type=EntityType.DOMAIN, value_reference=domain_value),
                action="domain_dns",
                proposed_input=domain_value,
                status=status,
                gain=0.1 if already else 0.7,
                cost=0.25,
                source=SourceClass.PASSIVE_WEB,
                reason=(
                    "PASSIVE_WEB is not authorized by the case manifest."
                    if not passive_allowed
                    else "Repeating the identical DNS step has low immediate information gain."
                    if already else "A point-in-time DNS observation may add technical context."
                ),
            ))
        username_values = {
            item.value_reference for item in discovered_entities if item.entity_type is EntityType.USERNAME
        }
        for username in sorted(username_values):
            already = "username_lookup" in executed_collectors
            status = (
                PivotStatus.BLOCKED if not passive_allowed
                else PivotStatus.LOW_VALUE if already
                else PivotStatus.RECOMMENDED
            )
            pivots.append(self._candidate(
                from_entity=EntityRef(entity_type=EntityType.USERNAME, value_reference=username),
                action="username_lookup",
                proposed_input=username,
                status=status,
                gain=0.1 if already else 0.65,
                cost=0.5,
                source=SourceClass.PASSIVE_WEB,
                reason=(
                    "PASSIVE_WEB is not authorized by the case manifest."
                    if not passive_allowed
                    else "The same username lookup step already ran."
                    if already else "A visible public handle can be checked as a profile candidate."
                ),
            ))
        company_values = {
            item.value_reference for item in discovered_entities if item.entity_type is EntityType.COMPANY
        }
        for company in sorted(company_values):
            pivots.append(self._candidate(
                from_entity=EntityRef(entity_type=EntityType.COMPANY, value_reference=company),
                action="company_web_research",
                proposed_input=company,
                status=PivotStatus.BLOCKED if not passive_allowed else PivotStatus.OPTIONAL,
                gain=0.55,
                cost=0.5,
                source=SourceClass.PASSIVE_WEB,
                reason=(
                    "PASSIVE_WEB is not authorized by the case manifest."
                    if not passive_allowed
                    else "Future reviewed company-web research may test this possible public association."
                ),
            ))
        return tuple(sorted(pivots, key=lambda item: (-item.expected_information_gain, item.action)))

    @staticmethod
    def _candidate(*, from_entity: EntityRef, action: str, proposed_input: str, status: PivotStatus,
                   gain: float, cost: float, source: SourceClass, reason: str) -> PivotCandidate:
        digest = hashlib.sha256(f"{action}|{source.value}|{proposed_input}".encode()).hexdigest()[:16]
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
