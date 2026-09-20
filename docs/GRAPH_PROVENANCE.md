# Graph Provenance v1

## IMPLEMENTED

Every node/edge binds to evidence and source references. Edges also retain source-independence groups. Run records bind graph versions to collector versions, provider configuration hash, policy hash, timestamps and evidence refs. The trace is collector observation → evidence item → graph node/edge → path/hypothesis/dossier.

Source copies share independence groups. `detect_circular_provenance()` identifies entity-reference cycles; graph path scoring penalizes them rather than counting a loop as independent corroboration.

## PLANNED

- External witnessing, signed exports and reviewer-corrected provenance groups.

## NOT IMPLEMENTED

- Tamper-proof claims, third-party timestamp authority or raw evidence bodies in GraphML/viewer.
