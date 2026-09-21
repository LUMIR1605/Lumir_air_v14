# Source Coverage v1

## IMPLEMENTED

The private dossier, JSON/HTML report and Windows summary expose per-entity coverage for PHONE, EMAIL, USERNAME, DOMAIN, WEBSITE, COMPANY, ORGANIZATION and DOCUMENT: eligible, enabled, executed, blocked, unknown and successful sources, verified evidence references and independent groups. Counts use the explicit execution mapping stored with each `CaseExecutionRecord`; an executed `phone_public_web` record therefore maps deterministically to `duckduckgo_html` instead of the collector name.

Stage 15.1 separates `DIRECT SOURCES` from `DOWNSTREAM SOURCES`. A source made eligible by a discovered WEBSITE/EMAIL/DOMAIN is labelled `DOWNSTREAM_ELIGIBLE` until its adapter actually executes. The aggregate executed count is the unique set of registry source IDs observed in real execution records. Local collectors remain visible as direct logical sources but do not pretend to be public `SourceRegistry` entries.

`SourceDiversityScore` measures independent source classes/domains plus first-party/archive and technical/textual mix. It is a coverage metric, not confidence or truth.

The GUI also reports initial collectors, automatic pivots, hop 1/2 counts, new relations and the exact loop stop reason.

## NOT IMPLEMENTED

- Public telemetry or cross-user/provider analytics.
