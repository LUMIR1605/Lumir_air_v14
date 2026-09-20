"""Bounded Common Crawl index adapter for temporal snapshot candidates."""

from datetime import datetime, timezone
import json
from typing import Callable, Mapping
from urllib.parse import quote, urlsplit

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation
from .phone_public_http import RequestsPhonePublicHttpClient
from .target_page_fetcher import canonicalize_url


class PublicArchiveCollector(Collector):
    agent_name = "public_archive"
    agent_type = "WEBSITE"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    collection_info_url = "https://index.commoncrawl.org/collinfo.json"

    def __init__(self, *, http_client=None, clock: Callable[[], datetime] | None = None,
                 max_snapshots: int = 5) -> None:
        super().__init__()
        self._http = http_client or RequestsPhonePublicHttpClient(max_body_bytes=262_144)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not 1 <= max_snapshots <= 10:
            raise ValueError("max_snapshots must be between 1 and 10")
        self._max = max_snapshots

    def validate_input(self, seed_reference: str) -> None:
        self._target(seed_reference)

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        target = self._target(seed_reference)
        try:
            info = self._http.get(self.collection_info_url, timeout=8.0,
                                  headers={"User-Agent": "LumirOSINTLab-PublicArchive/1.0"})
            collections = json.loads(info.body) if info.status_code == 200 else []
            api = str(collections[0]["cdx-api"]) if isinstance(collections, list) and collections else ""
            if not api.startswith("https://index.commoncrawl.org/"):
                raise ValueError("untrusted archive index endpoint")
            request_url = f"{api}?url={quote(target, safe='')}&output=json&limit={self._max}"
            response = self._http.get(request_url, timeout=8.0,
                                      headers={"User-Agent": "LumirOSINTLab-PublicArchive/1.0"})
        except Exception:
            return (self._unknown(target, "ARCHIVE_FAILURE"),)
        if response.status_code == 429:
            return (self._unknown(target, "RATE_LIMITED"),)
        if response.status_code != 200 or response.body_truncated:
            return (self._unknown(target, "ARCHIVE_UNKNOWN"),)
        snapshots = []
        try:
            for line in response.body.splitlines()[:self._max]:
                item = json.loads(line)
                if not isinstance(item, dict) or not item.get("timestamp") or not item.get("url"):
                    continue
                snapshots.append({key: item.get(key) for key in
                                  ("url", "timestamp", "status", "mime", "digest", "filename", "offset", "length")})
        except (TypeError, json.JSONDecodeError):
            return (self._unknown(target, "PARSER_FAILURE"),)
        if not snapshots:
            return (self._unknown(target, "NO_DATA"),)
        return (RawObservation(raw_status="FOUND", value_reference=f"archive:{target}",
            notes="Historical snapshot candidates only; they do not describe current state.",
            payload={"source_id": "common_crawl_index", "source_role": "ENRICHMENT",
                     "source_reputation": "ARCHIVE", "target": target, "snapshots": snapshots,
                     "temporal_evidence": True, "current_evidence": False,
                     "collected_at": self._clock().isoformat(), "failure_status": "SUCCESS"}),)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        return FindingCandidate(raw_status=f"ARCHIVE_{observation.raw_status}",
            normalized_status=FindingStatus.POSSIBLE if observation.raw_status == "FOUND" else FindingStatus.UNKNOWN,
            value_reference=observation.value_reference, evidence_ref=observation.evidence_ref,
            notes="Archive result is historical discovery/enrichment and is never current ownership proof.")

    def describe_capabilities(self) -> Mapping[str, object]:
        return {"network": True, "method": "GET", "temporal_evidence": True,
                "max_snapshots": self._max, "authentication": False, "current_claim": False}

    @staticmethod
    def _target(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("archive input must be non-empty")
        candidate = value.strip()
        if "://" not in candidate:
            candidate = "https://" + candidate.casefold().rstrip(".") + "/"
        target = canonicalize_url(candidate)
        if not urlsplit(target).hostname:
            raise ValueError("archive input must contain a host")
        return target

    @staticmethod
    def _unknown(target: str, reason: str) -> RawObservation:
        return RawObservation(raw_status="UNKNOWN", value_reference=f"archive:{target}",
                              notes="Archive lookup was inconclusive.",
                              payload={"source_id": "common_crawl_index",
                                       "failure_status": reason, "error_reason": reason})
