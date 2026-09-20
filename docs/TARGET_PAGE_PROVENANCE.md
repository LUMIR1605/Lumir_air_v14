# Target Page Provenance v1

## IMPLEMENTED

Accepted evidence preserves the trace:

`seed -> discovery provider/query/result -> target fetch/final canonical URL -> target body hash -> phone signal/context -> extracted entity -> correlation`

Payload fields include discovery channels, target fetch metadata, canonical URL/domain, raw and normalized-content hashes, page role, match/signal type and path, bounded context, source date/warning, evidence reference and extracted entities. Search providers never become target independence groups.

Independence uses canonical target URL/domain, exact body hash and normalized visible-text hash. The same target discovered through multiple search providers is fetched and counted once; copied content does not add independent corroboration.

## PLANNED

- Durable source lineage graph and reviewer-corrected duplicate groups.

## NOT IMPLEMENTED

- ML near-duplicate detection, external source reputation or cryptographic third-party witnessing.
