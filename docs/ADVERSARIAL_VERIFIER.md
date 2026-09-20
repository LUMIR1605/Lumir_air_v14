# Adversarial Verifier Foundation v1

## IMPLEMENTED

`AdversarialVerifier` applies deterministic challenges. It records counter-questions, opposing evidence references, ambiguity reasons, alternative explanations, and one of `UNTESTED`, `SURVIVES`, `WEAKENED`, `REJECTED`, or `INCONCLUSIVE`. Rules flag username coincidence, missing independent support, copied source groups, and opposing evidence.

`GraphAdversarialVerifier` additionally tests path independence, circular provenance, username collision, stale-only edges and rejected/contradictory edges. Two independent groups survive better; copied or circular evidence never multiplies corroboration.

## PLANNED

- Broader relation-specific challenge libraries and first-party source classification.
- Reviewer recording of whether a counter-question was resolved.

## NOT IMPLEMENTED

- LLM/API review, autonomous verification, browser research, or automatic evidence collection.
