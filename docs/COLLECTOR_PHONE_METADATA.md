# PhoneMetadataCollector v1

## IMPLEMENTED

`PhoneMetadataCollector` is the first production collector in OSINT LAB. It performs local numbering-plan analysis with the installed `phonenumbers` data only.

Identity:

- `agent_name`: `phone_metadata`
- `agent_type`: `PHONE`
- `version`: `1.0.0`
- `source_class`: `LOCAL`
- `network_required`: `false`
- default region for numbers without a country prefix: `PL`

Accepted input forms include `+48...`, `48...`, a local Polish number, spaces, hyphens, and parentheses. A local number is never guessed as another country. Syntactically parsable but invalid or impossible numbers complete normally with an `UNKNOWN` candidate; only an actual collector error produces `FAILED`.

The optional JSON-safe `RawObservation.payload` contains the raw input, E.164, international and national formats, country and region codes, `valid`, `possible`, number type, locally available carrier/geographic labels, and local timezone data. Missing carrier or geocoder data is represented by `null`, never as a claim that an owner or entity was not found.

`build_default_registry()` creates a fresh registry and explicitly registers the collector with `phonenumbers` provenance. There is no global mutable registry. Execution remains guarded by the Etap 4 registry, PolicyGate, audit, single-use context, Evidence Vault, and receipt controls.

The full phone input may be stored in the private Evidence Vault. Audit metadata contains only its SHA-256 reference. The ExecutionReceipt contains evidence references and no phone input.

Static and runtime tests block or detect imports/calls through `requests`, `urllib`, `socket`, `subprocess`, and DNS-related modules. The collector imports only local `phonenumbers` functionality and performs no network operation.

## PLANNED

- Additional explicitly reviewed default regions, if case policy later requires them.
- Schema versioning for structured collector payloads.
- A user-facing case workflow that keeps phone evidence outside Git.

## NOT IMPLEMENTED

- Reverse lookup or owner identification.
- Person-to-phone relations or identity matching.
- Social-account discovery, spam reputation, or breach lookup.
- PhoneInfoga, Holehe, Sherlock, external APIs, web search, DNS, Tor, or direct-target access.
- Carrier/geographic metadata is not proof of the current operator, subscriber, owner, or physical location.
