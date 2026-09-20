# Email Public Web v1

## IMPLEMENTED

`EmailPublicWebCollector` performs bounded exact-query discovery and validates target pages through the Etap 13 SSRF/redirect guard. It distinguishes `EXACT_EMAIL_MATCH`, `STRUCTURED_EMAIL_MATCH`, `OBFUSCATED_EMAIL_MATCH`, `USERNAME_ONLY`, `REJECTED` and `UNKNOWN` semantics. Exact visible and `mailto:` values are evidence candidates. Obfuscated forms remain `POSSIBLE` with a reason. A local-part/username alone is never evidence.

The provider receives the exact email query; therefore the adapter is PASSIVE_WEB, has high privacy cost, requires case permission and is manual above the default automatic privacy threshold.

## NOT IMPLEMENTED

- Login, account recovery, signup probing, breach datasets or identity confirmation.
