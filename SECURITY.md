# Security policy

Report suspected vulnerabilities privately to the Zagros maintainers rather than opening a public issue containing exploit details or secret material.

Do not include access/refresh tokens, activation tickets, passwords, private keys, decrypted configurations, server credentials, or production URLs/logs in a report. Use synthetic reproductions and the committed deterministic interoperability vectors.

## Boundary

The SDK protects transport/authentication contracts and avoids persistence APIs for White-label raw config. It does not claim that runtime keys or decrypted configurations are impossible to extract. A device owner controlling the OS/runtime, a debugger, malware, or a compromised native tunnel component may read runtime material.

Applications integrating the SDK must use OS-secure storage, redact logs and crash reports, enforce `ClientPolicy.whiteLabel`, and stop/detach lease renewal when tunnel state ends.
