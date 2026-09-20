# Case Dossier Model v1

## IMPLEMENTED

`CaseDossier` separates case summary/seeds, key entities, key relations, important paths, hypotheses, verified and rejected findings, contradictions, timeline, evidence quality, unresolved questions, recommended pivots, reviewer decisions and coverage. Coverage distinguishes NO_VERIFIED_DATA, INSUFFICIENT_INDEPENDENCE and CONTRADICTORY instead of presenting an empty result as success.

Report schema 1.5 embeds the dossier and renders KEY ENTITIES, KEY RELATIONS, IMPORTANT PATHS, OPEN HYPOTHESES, CONTRADICTIONS, TIMELINE and NEXT BEST PIVOTS. FACT/RELATION/CORRELATION/HYPOTHESIS/VERIFICATION remain separate layers.

## PLANNED

- Redacted export profiles and reviewer-approved PDF presentation.

## NOT IMPLEMENTED

- Public sharing, automatic narrative, legal conclusion or identity verdict.

## ETAP 15 — IMPLEMENTED

`SOURCE COVERAGE` is embedded per PHONE, EMAIL, USERNAME, DOMAIN, COMPANY and DOCUMENT. It reports eligible/enabled/executed/blocked/unknown/successful sources, verified evidence references and independent groups, plus compact totals for GUI/report use. Source diversity remains a coverage metric and does not promote findings.
