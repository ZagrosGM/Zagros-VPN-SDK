# SDK connection lifecycle and reliability contract

This contract is normative for Zagros Official and White-label clients.

## 1. One-list acquisition attempts

One attempt is exactly:

```text
GET configs (once) → select → POST connection/start → GET configs/{same id}
```

A second list request is forbidden inside that attempt because listing supersedes prior unconsumed selectors. Selection must be deterministic at the call site. `ConfigAcquisition` implements this order and verifies selector, connection, envelope, Application key, device, core, protocol, and engine bindings.

## 2. Bounded expiry and intermittent-network recovery

Selectors normally expire after 60 seconds and sealed envelopes normally expire after 30 seconds. On `config_grant_expired`, `config_grant_consumed`, `config_grant_invalid`, `connection_required`, a locally detected envelope validity-window failure, or an indeterminate transport response, the current attempt is abandoned. The SDK obtains fresh authority and repeats the complete one-list sequence.

Recovery is bounded to two total attempts by default (one fresh-authority retry). Every network request has a fresh signed-request nonce. The SDK never blindly repeats the ambiguous consume request: it starts over with a newly listed selector. It does not retry invalid credentials, revocation, quota, device-limit, unsupported protocol, signature, binding, validation, or malformed-response errors. Server-side start is idempotent for the same device/core/protocol.

A rejected access token gets one bounded refresh followed by a complete new acquisition attempt. This behavior is required for unreliable and high-latency networks, including typical connectivity conditions in Iran. Users must not receive an opaque expiry failure while the safe recovery budget remains.

## 3. Lease renewal

Server connection leases are 60–300 seconds; the current default is 120 seconds. A stable tunnel is not sufficient authority by itself. While a tunnel should remain connected, the client must periodically call:

```text
GET /api/application/v1/connections/status?connection_id=...&renew=true
```

`ConnectionLifecycle` schedules renewal ahead of `not_after`. Its safety lead is one-third of the observed remaining lease, clamped to 20–60 seconds (a 120-second lease renews after about 80 seconds). Successful renewal replaces `not_after` and schedules the next renewal.

Transient transport, rate-limit, and server failures are retried only while time remains before the existing deadline. An access-token rejection receives one refresh because renewal is idempotent. Revocation, authorization, missing connection, validation, and other terminal failures stop scheduling and are emitted through `onRenewalError`; the client state machine must then stop the native tunnel.

Clients must detach or stop renewal when the tunnel is stopped, the user logs out, the device is revoked, or the application is disposed.

## 4. Raw-config lifetime

White-label callers pass decrypted bytes or normalized runtime fields directly to a native tunnel adapter and release references immediately after setup. They must not put bytes or secret fields into widget state, analytics, logs, clipboard, preferences, SQLite, cache, crash reports, or plaintext temporary files. `OpenedConfig.dispose()` performs a best-effort overwrite. Dart GC, strings, parser/runtime copies, and a device owner controlling the OS/process prevent any guaranteed-erasure or non-extractability claim.
