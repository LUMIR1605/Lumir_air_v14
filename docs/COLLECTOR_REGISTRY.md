# OSINT LAB collector registry

## IMPLEMENTED

`CollectorRegistry` is mandatory for the Orchestrator. A registration binds:

- `agent_name`, `agent_type`, `version`, and `source_class`;
- declared capabilities and `network_required`;
- provenance;
- the Python module and qualified class name as the implementation identifier.

Registration rejects duplicate names, missing metadata, unknown source classes, empty versions, network-capability inconsistency, and any declaration mismatch. Execution revalidates current declarations and exact Python class identity. An unregistered collector or a replacement class using an existing name is denied before an execution context is issued.

## PLANNED

- Package hashes, signed release manifests, compatibility policy, and reviewed enable/disable workflows.
- Registry persistence and administrative tooling.
- Process-level isolation for collector code.

## NOT IMPLEMENTED

- No production collector is registered.
- Module and class identity is provenance metadata, not a cryptographic software attestation.
- The in-process registry is not a sandbox against hostile imported Python code.
