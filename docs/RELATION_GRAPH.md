# OSINT LAB relation graph

## IMPLEMENTED

`osint_lab.correlation.RelationGraph` is an in-memory, single-case graph with validated `RelationNode` and `Relation` records.

Node types: `PERSON`, `EMAIL`, `PHONE`, `USERNAME`, `DOMAIN`, `WEBSITE`, `COMPANY`, `DOCUMENT`, `IMAGE`, `SOCIAL_PROFILE`, `IP`, `LOCATION`, and `OTHER`.

Relation types: `OWNS`, `USES`, `ASSOCIATED_WITH`, `MENTIONS`, `HOSTED_ON`, `REGISTERED_TO`, `LINKS_TO`, `SAME_IDENTIFIER`, `POSSIBLE_MATCH`, `CONTRADICTS`, and `DERIVED_FROM`.

Every relation has a unique relation ID, case ID, existing source and target node IDs, typed relation, optional confidence in `[0, 1]`, typed status, at least one evidence reference, timezone-aware creation time, and notes. Cross-case edges, missing endpoints, self-edges, duplicate IDs, invalid enums, and unsupported confidence values are rejected.

Nodes with the same username, name, URL, or other value remain separate nodes. Adding nodes never creates a relation and never merges identities. `SAME_IDENTIFIER` and `POSSIBLE_MATCH` are explicit evidence-backed relation labels, not proof that two nodes represent the same person.

## PLANNED

- Serialization under the vault `graph/` directory with integrity metadata.
- Query helpers, graph snapshots, provenance views, and reviewer decisions.
- Explicit proposal workflows for correlation and identity-review candidates.

## NOT IMPLEMENTED

- No automatic identity resolution, deduplication, entity merge, inference, or AI verdict.
- No graph database, persistence, visualization, scoring engine, or collector integration.
- No rule promotes `POSSIBLE_MATCH` to verified identity.
