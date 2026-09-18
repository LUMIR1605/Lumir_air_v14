"""Central fail-closed policy decision for future collectors."""

from dataclasses import dataclass
from enum import Enum

from osint_lab.case_manifest import CaseManifest, CaseStatus

from .sources import SourceClass


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_EXPLICIT_APPROVAL = "REQUIRE_EXPLICIT_APPROVAL"


@dataclass(frozen=True)
class PolicyResult:
    decision: PolicyDecision
    reason: str


class PolicyGate:
    """Evaluate manifest authorization without invoking an agent."""

    @staticmethod
    def decide(
        manifest: CaseManifest,
        *,
        agent_type: str,
        source_class: SourceClass,
    ) -> PolicyResult:
        if not isinstance(manifest, CaseManifest):
            raise ValueError("validated CaseManifest required")
        if not isinstance(agent_type, str) or not agent_type.strip():
            raise ValueError("agent_type required")
        if not isinstance(source_class, SourceClass):
            raise ValueError("known SourceClass required")
        if manifest.status not in {CaseStatus.AUTHORIZED, CaseStatus.ACTIVE}:
            return PolicyResult(PolicyDecision.DENY, f"case status {manifest.status.value} is not runnable")
        if agent_type not in manifest.allowed_agent_types:
            return PolicyResult(PolicyDecision.DENY, "agent type is not authorized")
        if source_class in manifest.forbidden_source_classes:
            return PolicyResult(PolicyDecision.DENY, "source class is explicitly forbidden")
        if source_class not in manifest.allowed_source_classes:
            return PolicyResult(PolicyDecision.DENY, "source class is not allowed by the manifest")
        if source_class is SourceClass.LOCAL:
            return PolicyResult(PolicyDecision.ALLOW, "local source allowed by active manifest")
        if source_class is SourceClass.PASSIVE_WEB:
            return PolicyResult(PolicyDecision.ALLOW, "passive web source allowed by active manifest")
        if source_class is SourceClass.THIRD_PARTY_API and not manifest.third_party_api_allowed:
            return PolicyResult(PolicyDecision.DENY, "third-party API flag is disabled")
        if source_class is SourceClass.TOR and not manifest.tor_allowed:
            return PolicyResult(PolicyDecision.DENY, "Tor flag is disabled")
        if source_class is SourceClass.DIRECT_TARGET and not manifest.direct_target_allowed:
            return PolicyResult(PolicyDecision.DENY, "direct target flag is disabled")
        return PolicyResult(
            PolicyDecision.REQUIRE_EXPLICIT_APPROVAL,
            f"{source_class.value} requires per-run explicit approval",
        )
