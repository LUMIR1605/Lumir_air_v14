# Timeline Engine v1

## IMPLEMENTED

`TimelineEvent` supports FIRST_SEEN, LAST_SEEN, RELATION_APPEARED, RELATION_DISAPPEARED, ATTRIBUTE_CHANGED, CONFLICT_DETECTED, SOURCE_UPDATED and OTHER. Events require an explicit timestamp source and evidence references. Entity, relation and evidence event tables retain repeated observations; old facts are not deleted when newer data arrives.

## PLANNED

- Deterministic relation-disappearance windows and analyst-entered temporal corrections.

## NOT IMPLEMENTED

- Invented dates, inferred chronology without evidence or automatic historical truth resolution.
