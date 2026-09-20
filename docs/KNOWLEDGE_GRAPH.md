# Knowledge Graph v1

## IMPLEMENTED

Each case has a versioned SQLite graph under `%LOCALAPPDATA%\LumirOSINTLab\cases\<case_id>\graph\knowledge_graph.sqlite3`. `GraphStore` enables foreign keys, full synchronous writes, WAL journaling, transactional batches, deterministic IDs, append-safe entity/relation/evidence event tables, case events, pivot history, run records, schema metadata and migration history. Data never belongs in Git.

The graph stores evidence-backed nodes and relations, temporal bounds, source references, independence groups, review effects and graph versions. Existing case files are not rewritten; a graph is created lazily for a new graph-enabled run.

## PLANNED

- Explicit v2 migration scripts when a second schema exists; encrypted-at-rest case storage.

## NOT IMPLEMENTED

- Cross-case graph, server database, Redis/Kafka/Postgres, cloud sync or automatic identity merge.

## ETAP 15 — IMPLEMENTED

Reviewed source adapters project evidence through explicit adapters into PHONE, EMAIL, USERNAME, DOMAIN, WEBSITE, COMPANY/ORGANIZATION and DOCUMENT nodes. Cross-type relations are created only from accepted source semantics and retain source ID, evidence reference, independence group, reputation class and temporal/stale attributes. `ENTITY_DISCOVERED` records parent, source, extraction method, confidence and timestamp. Discovery-only results do not create evidence edges.
