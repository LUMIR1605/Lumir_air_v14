# LUMIR OSINT LAB v1 — architecture boundary

`SEED → ORCHESTRATOR → AGENTS / COLLECTORS → NORMALIZER → RAW EVIDENCE → CORRELATION ENGINE → VERIFICATION ENGINE → CONFIDENCE ENGINE → EVIDENCE VAULT → REPORT ENGINE`

This is a planned pipeline, not a claim of implemented collection. `osint_lab/` owns contracts plus local case, policy, evidence, graph and contradiction foundations; it contains no runnable collector. Existing `shield/` remains the functioning RC6 self-audit; an adapter can be designed after evidence and consent policy review. No SHIELD module is automatically registered.

| Stage | Contract / responsibility |
| --- | --- |
| Seed | Authorized case identifier, entity and narrowly scoped collection purpose; private case material stays outside Git. |
| Orchestrator | Enforces manifest, PolicyGate, scoped per-run approval when required, append-only audit, and single-use execution context before invoking a collector. Budgets, rate limits and durable approval lookup remain planned. |
| Agents / collectors | Declare stable name, type, version and `source_class`; guarded `run()` requires an orchestrator-issued context and returns raw observations, never final identity or verification claims. |
| Normalizer | Preserves raw status and source provenance; `FOUND` maps to `POSSIBLE` at most without separate review. |
| Raw evidence | Capture original response, timestamps, provenance, collection method, content hash and errors. No fabricated evidence. |
| Correlation engine | Propose links with explicit alternatives; matching identifier alone never proves a person or account owner. |
| Verification engine | Check independent evidence, contradictions and source freshness; record reviewer decisions. |
| Confidence engine | Assign documented calibrated confidence to a specific claim; unknown is allowed. A numeric score is not a verification decision. |
| Evidence vault | Local plaintext case directory outside repo with integrity hashes and atomic publication; encryption, access hardening, retention enforcement and deletion remain deferred. |
| Report engine | Clearly separate observations, hypotheses, verified facts, unavailable sources and collection limitations. |

Planned agents: `PhoneAgent`, `EmailAgent`, `UsernameAgent`, `DomainAgent`, `WebArchiveAgent`, `DocumentAgent`, `ImageMetadataAgent`, `TorResearchAgent`, `CorrelationAgent`, `VerificationAgent`, `ReportAgent`. These are architecture roles, not runnable collectors. Tor research and external crawlers are out of scope. SHIELD DNS, phone metadata, HIBP, GitHub and Holehe may be adapted later with their actual exposure classification and opt-in authorization.

| Source class | Exposure |
| --- | --- |
| `LOCAL` | Case data stay on the computer; no outbound requests. |
| `PASSIVE_WEB` | Query reaches a public web source; search logs may include an identifier. |
| `THIRD_PARTY_API` | Identifier may be shared with an external API operator. |
| `TOR` | Only legal publicly accessible Tor sources in an isolated environment, deferred. |
| `DIRECT_TARGET` | May contact target infrastructure; disabled by default and requires explicit future policy and case authorization. |

Finding schema: `case_id`, `entity_type`, `value`, `relation`, `source_name`, `source_url`, `source_class`, `collection_method`, `collected_at` (timezone-aware), `raw_status`, `normalized_status`, `confidence` (0–1 or unknown), `evidence_ref`, `artifact_hash` (SHA-256 or unknown), `notes`. Normalized statuses: `CONFIRMED`, `PROBABLE`, `POSSIBLE`, `UNKNOWN`, `NOT_FOUND`, `FALSE_POSITIVE`. `CONFIRMED` requires a separate verification step with recorded evidence; a collector's `FOUND` cannot automatically grant it. `NOT_FOUND` means only that a defined source and query returned no match, not that the entity does not exist.

Foundation v3 adds scoped expiring RunAuthorization, mandatory orchestrator enforcement, a local append-only JSONL audit API, single-use ExecutionContext, and Collector Contract v1. Only synthetic test collectors exist. It does not implement production collection, signed approvals, tamper-proof logging, encrypted storage, graph persistence, automatic identity resolution or AI verdicts.

Use only for authorized OSINT, self-audit and lawful research. No bypassing access controls, credential misuse, exploitation, unauthorized logins, illegal breach databases or evasion. Keep case data in a private folder outside the repository, for example `%LOCALAPPDATA%/LumirOSINTLab/cases`; ignore accidental in-repo case paths as defense in depth. Reports, logs and raw artifacts must not be committed.
