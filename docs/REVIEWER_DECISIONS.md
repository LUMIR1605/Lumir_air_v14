# Reviewer Decisions v1

## IMPLEMENTED

`ReviewerDecision` records decision ID, reviewer, timestamp, decision (`CONFIRM`, `REJECT`, `KEEP_OPEN`), target type/ID, notes, and evidence references. `ReviewerDecisionEngine` validates the target. Only a matching `CONFIRM` can promote a correlation to `CONFIRMED` or a hypothesis to `VERIFIED`.

No automatic review runs in CaseRunner. Promotion is an explicit human action and is represented separately from collector, correlation, and hypothesis output.

Etap 14 adds `ReviewerDecisionEvent` persistence in the case SQLite graph. Every change is a new row with evidence refs and optional previous-decision reference. Relations are materialized as CONFIRMED/REJECTED/POSSIBLE; hypotheses and identity candidates receive a separate VERIFIED/REJECTED/OPEN review effect. Original evidence and prior decisions remain. The hash-chained audit records only decision/target references and a target hash, never notes or raw identifiers.

## PLANNED

- UI workflow, reviewer authorization policy and cryptographic signing/key management.

## NOT IMPLEMENTED

- Electronic signatures, key management, automatic approval, or reviewer identity federation.
