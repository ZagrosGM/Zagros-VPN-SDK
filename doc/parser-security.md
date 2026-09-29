# Runtime parser security contract

The SDK parses only bounded runtime input. It does not start a process, read referenced files, resolve DNS, or write configuration data.

## Global bounds

- Maximum input: 256 KiB.
- Maximum list/map width: 512 parser items; generic API JSON normalization also has a 1,000-item defensive bound.
- Maximum parser nesting: 24 levels; generic JSON normalization rejects depth beyond 32.
- Hosts are non-empty, at most 253 characters, and cannot contain whitespace, NUL, slash, or backslash.
- Ports are integers from 1 through 65,535.
- Unsupported URI schemes fail closed.

## Supported representations

- Share URIs: VLESS, VMess, Trojan, Shadowsocks, Hysteria 2, TUIC, AnyTLS, SOCKS, HTTP(S), SSH, PPTP, and L2TP/IPsec.
- JSON/YAML: sing-box and Clash proxy definitions.
- Native text: WireGuard INI and OpenVPN profiles.
- Structured Application driver payloads, including SSH and legacy PPTP/L2TP fields.

Unknown protocol-specific mapping fields are retained in immutable `options`/`extensions` runtime structures rather than silently discarded. Full sing-box/Clash documents are retained as runtime extensions so routing/groups and future fields remain available to native adapters.

## File and execution denial

OpenVPN script/plugin directives are rejected. External key, certificate, CA, CRL, PKCS#12, static-secret, and credential-file references are rejected; security material must be inline. Unmatched, duplicate, unsupported, or unclosed inline blocks are rejected. Recognized JSON/YAML/driver file and security-path fields are also rejected and are never dereferenced. WireGuard rejects unknown sections and preserves all Interface and Peer fields, including multiple peers.

These checks reduce parser attack surface but do not make an untrusted VPN endpoint safe. Native adapters must apply their own protocol validation and platform sandboxing.

## Legacy platform warning

PPTP is marked `legacy_insecure`. L2TP/IPsec is marked `platform_support_conditional`. Neither is advertised as uniformly available on modern iOS and Android; the later platform client must capability-gate them.
