# Identity Resolution Foundation v1

## IMPLEMENTED

`IdentityCandidate` groups entity IDs with supporting/opposing graph paths, confidence, reasons and unresolved questions. Automatic states are OPEN, PLAUSIBLE, WEAKENED or REJECTED. VERIFIED is structurally impossible without a ReviewerDecision.

One phone, name, username or email never proves identity. Graph-path confidence uses the weakest link, independent-group count, evidence count, circular-provenance penalty and contradiction penalty.

## PLANNED

- Manual candidate review UI and reviewer-authentication policy.

## NOT IMPLEMENTED

- Automatic person identity, face/biometric matching, ownership conclusion or cross-case identity search.
