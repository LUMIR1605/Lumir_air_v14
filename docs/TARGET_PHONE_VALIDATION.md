# Target Phone Validation v1

## IMPLEMENTED

`TargetPhoneValidator` compares normalized Polish local, `+48`, and `0048` forms but requires telephone semantics. Accepted classes are `PHONE_CONTEXT_MATCH` and `STRUCTURED_PHONE_MATCH`. Structured signals include `tel:`, schema/microdata telephone, meta phone/telephone, JSON-LD telephone and vCard TEL.

Visible matches retain only a bounded context before/after the matched text. Generic numeric equality becomes `NUMERIC_MATCH_ONLY`; URL/resource, product, image, article and similar identifiers become `REJECTED_NUMERIC_ID`; absent values become `UNKNOWN`. Only accepted target matches may feed extraction and Intelligence Core.

## PLANNED

- Additional reviewed locale dictionaries and deterministic structured-contact formats.

## NOT IMPLEMENTED

- Person inference, ownership resolution, OCR, LLM interpretation or fuzzy digit matching.
