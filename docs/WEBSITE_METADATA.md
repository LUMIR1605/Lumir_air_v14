# Website Metadata Collector v1

## IMPLEMENTED

`WebsiteMetadataCollector` accepts a public HTTP(S) URL or domain and uses `TargetPageFetcher`. It retains final URL, redirect chain, title, description, canonical URL, selected public server/language headers, TLS subject/SAN/expiry when available, content language, JSON-LD organization/contact fields and visible public email/phone/domain signals.

Every redirect and peer address remains subject to SSRF/DNS-rebinding checks. No JavaScript, cookies, login or active interaction is used.

## NOT IMPLEMENTED

- Browser rendering, authenticated pages or ownership conclusions.
