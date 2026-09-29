# Zagros VPN SDK

Pure-Dart SDK for Zagros Official and White-label clients.

It owns the versioned Application API contract, per-installation X25519 identity, canonical signed requests, token/session orchestration, signed config-envelope opening, normalized VPN models, bounded config acquisition recovery, renewable connection leases, and the policy-bound Official profile library. It has no Flutter dependency and does not implement native tunnels or UI.

## Security boundary

- No Application private key or shared installation secret is embedded.
- Each installation uses an independent X25519 key pair supplied by an OS-secure storage adapter.
- The Official profile repository persists bounded raw sources only through a caller-supplied OS-secure store and only when Official policy grants `rawConfigPersistence`.
- White-label policy denies the Official repository and catalog store before storage or subscription transport is reached. White-label Application configurations remain runtime-only objects/bytes.
- Runtime material may still be extracted by a device owner who controls the OS/process. The SDK does not claim otherwise.
- Application clients communicate only with the panel. Node-control credentials and routes are not part of this package.

## Main components

- `DeviceIdentityManager`: creates/loads one installation-specific X25519 key pair through a caller-supplied OS-secure store.
- `SignedRequestExecutor` and `ApplicationApi`: exact-byte request authentication and all `/api/application/v1` methods.
- `ApplicationAuthController` / `ApplicationSession`: enrollment, login, refresh coalescing, restore, logout, and secure token-state orchestration.
- `AuthenticatedApplicationClient`: read-only authenticated profile/device/config/connection/usage methods with one safe access-token refresh.
- `ConfigAcquisition`: the only high-level sealed-config retrieval path; it binds list, selection, lease start, consume, signature verification, decryption, normalization, and bounded recovery.
- `ConnectionLifecycle`: proactive lease renewal with bounded transient-failure handling.
- `ClientPolicy`: explicit Official versus White-label capability guards.
- `OfficialConfigParser`: bounded aggregate detection over the existing share URI, WireGuard, OpenVPN, Clash, and sing-box parsers.
- `HttpOfficialSubscriptionClient`: bounded HTTPS subscription retrieval with stable Official device identity, same-origin redirects, conditional refresh, and Zagros metadata parsing.
- `OfficialProfileRepository`: serialized policy-bound subscription/manual CRUD over two-slot protected catalog persistence.

The complete Official library contract is documented in [`doc/official-profile-library.md`](doc/official-profile-library.md).

The host Flutter/native application must provide `SecureValueStore` and `SecureTokenStore` implementations backed by platform security facilities. A White-label build must not provide plaintext file, preferences, or database fallbacks.

## Required acquisition and lease behavior

See [`doc/reliability-and-lease-contract.md`](doc/reliability-and-lease-contract.md). The three non-optional rules are:

1. `list once → select → start/renew → immediate consume` with no second list in the attempt.
2. Bounded safe recovery from 60-second selector and 30-second envelope expiry or intermittent transport loss.
3. Proactive `renew=true` before every 60–300 second lease expires (default server lease: 120 seconds).

Parser limits and file-reference denial are specified in [`doc/parser-security.md`](doc/parser-security.md). OpenVPN static-auth omission is specified in [`doc/openvpn-static-auth.md`](doc/openvpn-static-auth.md).

## Product policy

- Official mode can enable subscription import, manual configuration, and raw-config export/display under explicit UI policy; it does not require Application login for those paths.
- White-label mode requires username/password **and** the enrolled Application/device cryptographic identity. It disables subscription import, manual config entry, raw-config display/export/clipboard, and raw-config persistence.
- The one-time activation ticket is delivered separately from username/password by the reseller/admin workflow. It binds enrollment; credentials alone cannot enroll a new device or retrieve a configuration.
- PPTP/L2TP support is platform-conditional and is not claimed as fully cross-platform.

## Development

```bash
dart pub get
dart format --output=none --set-exit-if-changed .
dart analyze
dart test
```

This repository is currently local and uncommitted. No artifact or package has been published.
