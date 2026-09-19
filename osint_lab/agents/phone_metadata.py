"""Local-only phone numbering metadata backed by phonenumbers."""

import re
from typing import Mapping

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation


_ALLOWED_INPUT = re.compile(r"^[+0-9\s()\-]+$")


class PhoneMetadataCollector(Collector):
    """Analyze numbering-plan metadata without network access or identity lookup."""

    agent_name = "phone_metadata"
    agent_type = "PHONE"
    version = "1.0.0"
    source_class = SourceClass.LOCAL
    network_required = False
    default_region = "PL"

    def validate_input(self, seed_reference: str) -> None:
        self._parse(seed_reference)

    def _run(
        self,
        context: ExecutionContext,
        seed_reference: str,
    ) -> tuple[RawObservation, ...]:
        number = self._parse(seed_reference)
        possible = phonenumbers.is_possible_number(number)
        valid = phonenumbers.is_valid_number(number)
        carrier_name = carrier.name_for_number(number, "en").strip() or None
        geographic_description = geocoder.description_for_number(number, "en").strip() or None
        normalized_e164 = phonenumbers.format_number(number, PhoneNumberFormat.E164)
        payload = {
            "raw_input": seed_reference,
            "normalized_e164": normalized_e164,
            "international_format": phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL),
            "national_format": phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL),
            "country_code": number.country_code,
            "region_code": phonenumbers.region_code_for_number(number),
            "valid": valid,
            "possible": possible,
            "number_type": PhoneNumberType.to_string(phonenumbers.number_type(number)),
            "carrier_name": carrier_name,
            "geographic_description": geographic_description,
            "timezones": list(timezone.time_zones_for_number(number)),
        }
        unavailable: list[str] = []
        if carrier_name is None:
            unavailable.append("carrier")
        if geographic_description is None:
            unavailable.append("geographic description")
        suffix = f" Local metadata unavailable: {', '.join(unavailable)}." if unavailable else ""
        return (
            RawObservation(
                raw_status="PHONE_METADATA" if valid else "UNKNOWN",
                value_reference=normalized_e164,
                notes=(
                    "Local numbering-plan metadata only; no owner, identity, account, "
                    f"reputation, or reverse-lookup inference.{suffix}"
                ),
                payload=payload,
            ),
        )

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        if not isinstance(observation, RawObservation):
            raise ValueError("RawObservation required")
        valid = observation.payload.get("valid") is True
        return FindingCandidate(
            raw_status=observation.raw_status,
            normalized_status=FindingStatus.POSSIBLE if valid else FindingStatus.UNKNOWN,
            value_reference=observation.value_reference,
            evidence_ref=observation.evidence_ref,
            notes="Technical phone-number metadata; never an identity or ownership confirmation.",
        )

    def describe_capabilities(self) -> Mapping[str, object]:
        return {
            "network": False,
            "default_region": self.default_region,
            "numbering_plan_metadata": True,
            "reverse_lookup": False,
            "owner_identification": False,
        }

    def _parse(self, seed_reference: str):
        if not isinstance(seed_reference, str) or not seed_reference.strip():
            raise ValueError("phone input must be non-empty")
        raw = seed_reference.strip()
        if _ALLOWED_INPUT.fullmatch(raw) is None:
            raise ValueError("phone input contains unsupported characters")
        compact = re.sub(r"[\s()\-]", "", raw)
        if compact.count("+") > 1 or ("+" in compact and not compact.startswith("+")):
            raise ValueError("phone input has an invalid international prefix")
        digits = compact[1:] if compact.startswith("+") else compact
        if not digits.isdigit():
            raise ValueError("phone input must contain digits")
        if compact.startswith("+"):
            value, region = compact, None
        elif digits.startswith("48") and len(digits) > 9:
            value, region = f"+{digits}", None
        else:
            value, region = digits, self.default_region
        try:
            return phonenumbers.parse(value, region)
        except phonenumbers.NumberParseException as error:
            raise ValueError("phone input could not be parsed") from error
