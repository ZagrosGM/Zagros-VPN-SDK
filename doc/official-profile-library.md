# Official profile library contract

## Ownership

The SDK owns Official profile models, parsing, subscription transport, stable subscription identity, validation, persistence encoding, CRUD sequencing, and product-policy decisions. Flutter may hold transient presentation state and invoke these APIs, but must not duplicate this logic.

`OfficialProfileRepository` is the supported high-level entry point. Its policy must match the `SecureOfficialCatalogStore` policy. White-label policy denies repository and direct catalog-store operations before storage or subscription transport is reached.

## Subscription identity and transport

Official subscription enrollment uses a random 32-byte opaque `zg_` identifier persisted through `SecureValueStore`. It is intentionally separate from the Application X25519 device identity and is never inferred from source IP or User-Agent.

`HttpOfficialSubscriptionClient`:

- sends the stable value as `X-Device-ID`;
- accepts HTTPS URLs and loopback HTTP only;
- rejects URL user-info and fragments;
- handles at most three redirects by default;
- follows same-origin redirects only, preventing token-bearing URLs from being disclosed to another origin;
- requests the non-browser payload and bounds response bytes and time;
- parses base64 merged-link payloads, share-link lists, WireGuard, OpenVPN, Clash, and sing-box through authoritative SDK parsers;
- supports `ETag`, `Last-Modified`, `subscription-userinfo`, and `profile-update-interval`; and
- maps authentication, authorization/revocation, throttling, malformed response, and transport failures to low-information SDK errors.

A failed refresh does not replace the stored profile. An unsolicited `304 Not Modified` cannot associate an old configuration with a changed subscription URL.

## Protected catalog

The catalog stores raw Official sources because users explicitly requested persistent Official profiles. The caller must supply an OS-protected `SecureValueStore`; plaintext files, preferences, and databases are not valid implementations.

The codec is bounded to 128 profiles, 4 MiB total encoded data, 256 KiB per source, and 48 KiB protected-store chunks. It reparses every stored raw source into authoritative normalized models when loading. IDs, names, URLs, timestamps, metadata, JSON shape, parser limits, and config-entry correspondence are validated.

Writes alternate between two chunk slots. Inactive chunks are written first and a SHA-256-bearing manifest is replaced last. Therefore, an interrupted chunk or manifest write leaves the previous manifest and catalog readable. After a successful manifest replacement, the previously active protected chunks are deleted on a best-effort basis; a process crash or platform cleanup refusal can leave inaccessible protected-store remnants. SHA-256 here is an integrity check inside OS-protected storage, not a substitute for that storage's confidentiality or platform access controls.

## Raw controls

SDK policy distinguishes raw display, clipboard, export, and persistence. Official UI must check the relevant capability for each action and warn that clipboard/export can disclose credentials. White-label policy denies all of these capabilities. A device owner controlling the OS or process may still extract runtime material; the SDK does not claim otherwise.

## Tunnel boundary

Official normalized models may be selected and passed to the separate `TunnelAdapter` boundary. This SDK does not provide a native tunnel adapter and does not infer a connected state. Until a platform adapter confirms connection, clients must present the profile as unavailable or pending rather than connected.
