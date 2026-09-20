# LUMIR OSINT LAB v1 — architecture boundary

`SEED → ORCHESTRATOR → AGENTS / COLLECTORS → NORMALIZER → RAW EVIDENCE → CORRELATION ENGINE → VERIFICATION ENGINE → CONFIDENCE ENGINE → EVIDENCE VAULT → REPORT ENGINE`

This is a staged pipeline, not a claim that every stage is implemented. `osint_lab/` owns contracts plus local case, policy, evidence, graph and contradiction foundations. Production collectors include local phone/email metadata, exact phone/email public web validation, DNS, RDAP, website metadata, conservative GitHub/GitLab username checks, Gravatar exposure, exact structured company pages, bounded document intelligence and Common Crawl temporal candidates. Existing `shield/` remains the functioning RC6 self-audit and no SHIELD module is automatically registered.

| Stage | Contract / responsibility |
| --- | --- |
| Seed | Authorized case identifier, entity and narrowly scoped collection purpose; private case material stays outside Git. |
| Orchestrator | Enforces registry, manifest, PolicyGate, durable scoped approval when required, tamper-evident audit, single-use context, required vault publication, and execution receipt. Enrichment adds finite hop/pivot/privacy/request budgets and serial provider/host limits. |
| Agents / collectors | Declare stable name, type, version, `source_class`, capabilities and network use; registry validation precedes guarded `run()`, which returns raw observations, never final identity or verification claims. |
| Normalizer | Preserves raw status and source provenance; `FOUND` maps to `POSSIBLE` at most without separate review. |
| Raw evidence | Capture original response, optional JSON-safe structured payload, timestamps, provenance, collection method, content hash and errors. No fabricated evidence. |
| Correlation engine | Propose links with explicit alternatives; matching identifier alone never proves a person or account owner. |
| Verification engine | Check independent evidence, contradictions and source freshness; record reviewer decisions. |
| Confidence engine | Assign documented calibrated confidence to a specific claim; unknown is allowed. A numeric score is not a verification decision. |
| Evidence vault | Local plaintext case directory outside repo with SHA-256 metadata and atomic publication; execution records and receipts are integrated. Encryption, access hardening, retention enforcement and deletion remain deferred. |
| Report engine | Clearly separate observations, hypotheses, verified facts, unavailable sources and collection limitations. |

Implemented collectors cover local phone/email metadata, current-record DNS, public RDAP, SSRF-guarded website metadata, provider-specific GitHub/GitLab checks, public Gravatar profiles, exact public email occurrences, exact structured company pages, bounded PDF/TXT/HTML text extraction and Common Crawl index candidates. `ImageMetadataAgent` and `TorResearchAgent` remain non-runnable; broad external crawling is out of scope. SHIELD DNS, HIBP, GitHub and Holehe are not adapted or automatically registered.

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

Etap 10 adds a Tkinter Windows adapter without adding an execution path. CLI and desktop both use `application.py` as their composition root and manifest factory. The desktop backend creates a private case and calls the public CaseRunner; it cannot invoke a collector directly. A queue bridges the worker to the Tk UI thread, while optional CaseRunner progress notifications do not participate in enforcement and cannot change execution outcome. Report and folder actions validate paths against the expected private case root before opening them.

Etap 11 adds a deterministic post-collection intelligence pipeline: `Evidence Quality -> Correlation -> Hypothesis -> Adversarial Review -> Pivot Planner -> IntelligenceSummary -> Report`. It runs only after Orchestrator-controlled collection has finished and does not alter collector order, policy, registry, authorization, audit, vault, or receipt controls. Copies are clustered before corroboration. Correlation and hypothesis statuses remain explicitly separate from facts; only a `ReviewerDecision` can promote them to `CONFIRMED` or `VERIFIED`. The planner recommends but never executes work.

Etap 12 adds the first real phone public-web sensor without bypassing that pipeline. PHONE plans `phone_metadata` first and `phone_public_web` second. The public step is denied before HTTP unless `PASSIVE_WEB` is enabled. Only semantically validated phone-context or structured-telephone occurrences become direct technical evidence; numeric resource identifiers are rejected before correlation.

Etap 13 separates `SEARCH DISCOVERY -> RESULT CANDIDATE -> TARGET PAGE FETCH -> TARGET PHONE VALIDATION -> EXTRACTION -> INTELLIGENCE`. Search engines are discovery channels only. Target fetching is SSRF/redirect/content/size bounded, canonical targets are deduplicated, and target body plus normalized-text hashes drive copy clustering. Only accepted target evidence feeds neutral correlation, hypothesis and non-executing pivots. No automatic subscriber or owner conclusion is created.

Etap 14 adds `EnrichmentBus -> Orchestrator -> Evidence -> SQLite Knowledge Graph -> graph paths/timeline/adversarial review -> dossier/report`. Existing collectors are adapters, not rewritten execution paths. The graph is case-local outside Git, versioned and evidence-backed; it never replaces Evidence Quality as the source assessment. Multi-hop work is proposed under finite budgets and persistent loop suppression. Identity remains a review-only candidate, and durable decisions are append-only.

Etap 15 adds `SourceRegistry PRO -> reviewed Source Adapter -> EnrichmentBus -> Orchestrator -> Evidence -> Knowledge Graph`. Enabled sources must pass a hard public/automation/terms/privacy/credential/payment review. New adapters cover exact public email occurrences, IANA-bootstrapped RDAP, SSRF-guarded website metadata, exact structured company pages, bounded text-only documents and temporal Common Crawl index candidates. Provider health, private cache, per-case/provider/host request budgets, source diversity, independent corroboration, coverage reporting and source-rich synthetic benchmarks are local-only. CT, generic company registries/directories and Wayback CDX stay disabled where review is incomplete.

Use only for authorized OSINT, self-audit and lawful research. No bypassing access controls, credential misuse, exploitation, unauthorized logins, illegal breach databases or evasion. Keep case data in a private folder outside the repository, for example `%LOCALAPPDATA%/LumirOSINTLab/cases`; ignore accidental in-repo case paths as defense in depth. Reports, logs and raw artifacts must not be committed.
