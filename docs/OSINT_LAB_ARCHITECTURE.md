# LUMIR OSINT LAB v1 — architecture boundary

`SEED → ORCHESTRATOR → AGENTS / COLLECTORS → NORMALIZER → RAW EVIDENCE → CORRELATION ENGINE → VERIFICATION ENGINE → CONFIDENCE ENGINE → EVIDENCE VAULT → REPORT ENGINE`

This is a staged pipeline, not a claim that every stage is implemented. `osint_lab/` owns contracts plus local case, policy, evidence, graph and contradiction foundations. Production collectors are `PhoneMetadataCollector` v1 (`LOCAL`), `DomainDNSCollector` v1 (`PASSIVE_WEB`), conservative `UsernameCollector` v1 (`PASSIVE_WEB`), `EmailLocalMetadataCollector` v1 (`LOCAL`), and `EmailExposureCollector` v1 (`PASSIVE_WEB`). Existing `shield/` remains the functioning RC6 self-audit and no SHIELD module is automatically registered.

| Stage | Contract / responsibility |
| --- | --- |
| Seed | Authorized case identifier, entity and narrowly scoped collection purpose; private case material stays outside Git. |
| Orchestrator | Enforces registry, manifest, PolicyGate, durable scoped approval when required, tamper-evident audit, single-use context, required vault publication, and execution receipt. Budgets and rate limits remain planned. |
| Agents / collectors | Declare stable name, type, version, `source_class`, capabilities and network use; registry validation precedes guarded `run()`, which returns raw observations, never final identity or verification claims. |
| Normalizer | Preserves raw status and source provenance; `FOUND` maps to `POSSIBLE` at most without separate review. |
| Raw evidence | Capture original response, optional JSON-safe structured payload, timestamps, provenance, collection method, content hash and errors. No fabricated evidence. |
| Correlation engine | Propose links with explicit alternatives; matching identifier alone never proves a person or account owner. |
| Verification engine | Check independent evidence, contradictions and source freshness; record reviewer decisions. |
| Confidence engine | Assign documented calibrated confidence to a specific claim; unknown is allowed. A numeric score is not a verification decision. |
| Evidence vault | Local plaintext case directory outside repo with SHA-256 metadata and atomic publication; execution records and receipts are integrated. Encryption, access hardening, retention enforcement and deletion remain deferred. |
| Report engine | Clearly separate observations, hypotheses, verified facts, unavailable sources and collection limitations. |

Implemented collectors: local phone numbering metadata, current-record DNS through the configured resolver, provider-specific public username checks for GitHub/GitLab, local email syntax/provider-list metadata, and a conservative public Gravatar profile check using a SHA-256 email identifier. Planned roles remain `WebArchiveAgent`, `DocumentAgent`, `ImageMetadataAgent`, `TorResearchAgent`, `CorrelationAgent`, `VerificationAgent`, and `ReportAgent`; they are not runnable collectors. Tor research and broad external crawling are out of scope. SHIELD DNS, HIBP, GitHub and Holehe are not adapted or automatically registered.

| Source class | Exposure |
| --- | --- |
| `LOCAL` | Case data stay on the computer; no outbound requests. |
| `PASSIVE_WEB` | Query reaches a public web source; search logs may include an identifier. |
| `THIRD_PARTY_API` | Identifier may be shared with an external API operator. |
| `TOR` | Only legal publicly accessible Tor sources in an isolated environment, deferred. |
| `DIRECT_TARGET` | May contact target infrastructure; disabled by default and requires explicit future policy and case authorization. |

Finding schema: `case_id`, `entity_type`, `value`, `relation`, `source_name`, `source_url`, `source_class`, `collection_method`, `collected_at` (timezone-aware), `raw_status`, `normalized_status`, `confidence` (0–1 or unknown), `evidence_ref`, `artifact_hash` (SHA-256 or unknown), `notes`. Normalized statuses: `CONFIRMED`, `PROBABLE`, `POSSIBLE`, `UNKNOWN`, `NOT_FOUND`, `FALSE_POSITIVE`. `CONFIRMED` requires a separate verification step with recorded evidence; a collector's `FOUND` cannot automatically grant it. `NOT_FOUND` means only that a defined source and query returned no match, not that the entity does not exist.

Etap 7 adds controlled public username checks without changing the Etap 4 execution order or controls. PASSIVE_WEB must be explicitly allowed in the CaseManifest. Provider-specific signals, conservative ambiguity handling, audit privacy, Evidence Vault, and ExecutionReceipt are mandatory. A matching username is never identity confirmation. No authenticated scraping, social graph, CAPTCHA bypass, browser automation, Tor, ownership inference, graph persistence, or AI verdict is implemented.

Etap 8 preserves the one-source-class contract by separating local email metadata from passive public exposure checks. The local collector records a dependency reference to `domain_dns` but cannot execute it; DNS remains a separately registered, separately policy-evaluated run. The exposure collector sends only a provider-normalized SHA-256 identifier to a reviewed public endpoint. It does not use Holehe, login, signup, reset/recovery, authentication, CAPTCHA handling, subprocess, or browser automation. Email observations never confirm ownership or a person-email relationship.

Etap 9 adds an application layer without weakening the Etap 4 execution boundary. `CaseRunner` builds an explicit deterministic plan, then submits each allowed or denied step through the public Orchestrator. `CaseStore` keeps manifests, plans, and run summaries atomically outside Git. `ReportEngine` publishes private JSON/HTML reports through Evidence Vault before direct case-file publication, and binds them with SHA-256 evidence metadata. The CLI is a thin wrapper over these classes. No collector is invoked through `_run()`, and dry-run performs no collection or evidence publication.

Use only for authorized OSINT, self-audit and lawful research. No bypassing access controls, credential misuse, exploitation, unauthorized logins, illegal breach databases or evasion. Keep case data in a private folder outside the repository, for example `%LOCALAPPDATA%/LumirOSINTLab/cases`; ignore accidental in-repo case paths as defense in depth. Reports, logs and raw artifacts must not be committed.
