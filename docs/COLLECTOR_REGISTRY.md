# OSINT LAB collector registry

## IMPLEMENTED

`CollectorRegistry` is mandatory for the Orchestrator. A registration binds:

- `agent_name`, `agent_type`, `version`, and `source_class`;
- declared capabilities and `network_required`;
- provenance;
- the Python module and qualified class name as the implementation identifier.

Registration rejects duplicate names, missing metadata, unknown source classes, empty versions, network-capability inconsistency, and any declaration mismatch. Execution revalidates current declarations and exact Python class identity. An unregistered collector or a replacement class using an existing name is denied before an execution context is issued.

`build_default_registry()` creates a new registry for each caller and explicitly registers:

- `PhoneMetadataCollector` v1 with `LOCAL`, `network_required: false`, and installed `phonenumbers` provenance;
- `DomainDNSCollector` v1 with `PASSIVE_WEB`, `network_required: true`, and installed `dnspython` provenance;
- `UsernameCollector` v1 with `PASSIVE_WEB`, `network_required: true`, installed `requests` provenance, and a hash of the exact provider configuration.
- `EmailLocalMetadataCollector` v1 with `LOCAL`, `network_required: false`, stdlib IDNA provenance, and versioned incomplete provider-list metadata;
- `EmailExposureCollector` v1 with `PASSIVE_WEB`, `network_required: true`, installed `requests` provenance, and a hash of the exact reviewed provider configuration.

All registrations include declared capabilities and implementation identifiers. The factory does not expose a global mutable registry or perform a DNS or HTTP query. The local email collector cannot trigger the exposure collector; each must be executed and policy-evaluated independently.

## PLANNED

- Package hashes, signed release manifests, compatibility policy, and reviewed enable/disable workflows.
- Registry persistence and administrative tooling.
- Process-level isolation for collector code.

## NOT IMPLEMENTED

- No authenticated/private-profile, password-reset, signup/login probing, browser-automation, commercial API, Tor, direct-target, identity-confirmation, ownership, reverse-lookup, or threat-intelligence collector is registered. Holehe is not registered.
- Module and class identity is provenance metadata, not a cryptographic software attestation.
- The in-process registry is not a sandbox against hostile imported Python code.
