# Reviewer Decisions v1

## IMPLEMENTED

`ReviewerDecision` records decision ID, reviewer, timestamp, decision (`CONFIRM`, `REJECT`, `KEEP_OPEN`), target type/ID, notes, and evidence references. `ReviewerDecisionEngine` validates the target. Only a matching `CONFIRM` can promote a correlation to `CONFIRMED` or a hypothesis to `VERIFIED`.

No automatic review runs in CaseRunner. Promotion is an explicit human action and is represented separately from collector, correlation, and hypothesis output.

## PLANNED

- Durable append-only review storage, UI workflow, revocation/supersession, and reviewer authorization policy.

## NOT IMPLEMENTED

- Electronic signatures, key management, automatic approval, or reviewer identity federation.
