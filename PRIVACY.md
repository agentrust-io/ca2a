# Privacy

cA2A processes delegation credentials, task payloads, policy inputs, and provenance supplied by your application. These can contain sensitive metadata or content. Review the artifacts you retain or share; a provenance record is not automatically anonymous.

The runtime sends configured task and delegation data to the peer your application calls. Local signing and verification do not send project telemetry or analytics. Peer transport, application logging, and configured attestation or verification services determine the rest of the data flow.

Uninstalling the package does not delete generated credentials, provenance files, keys, logs, backups, or data already sent to a peer. Manage those artifacts through your application's retention and deletion procedures.

[Report a correction](https://github.com/agentrust-io/ca2a/issues).
