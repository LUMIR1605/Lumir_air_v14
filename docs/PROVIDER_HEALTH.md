# Provider Health v1

## IMPLEMENTED

`ProviderHealthStore` atomically persists case-private, local-only provider state outside Git: last success/failure, last status, parser version, consecutive failures, challenge detection and disabled reason. Statuses distinguish NO_DATA, NO_MATCH, UNKNOWN, BLOCKED, RATE_LIMITED, AUTH_REQUIRED, PAID_ONLY, TERMS_DISABLED, PARSER_FAILURE, TIMEOUT and UNSUPPORTED.

## NOT IMPLEMENTED

- External telemetry, remote monitoring or automatic re-enabling.
