import 'dart:convert';

import '../parsers/parser_limits.dart';

/// One `zagros-file:` marker from a subscription body: a file-backed config
/// (OpenVPN profile, WireGuard config...) the app fetches separately.
///
/// The panel emits markers as `# zagros-file: /sub/file/<token>/<core>/<tag>`
/// comment lines inside the subscription body (base64 envelope included), so
/// generic clients ignore them. The SDK resolves them against the
/// subscription URL — same origin only, never an absolute URL.
class OfficialFileRef {
  const OfficialFileRef({
    required this.coreId,
    required this.tag,
    required this.path,
  });

  /// Core that owns the file (`openvpn`, `wireguard`, ...).
  final String coreId;

  /// Listener tag, percent-decoded for display.
  final String tag;

  /// The panel-relative path, verbatim (`/sub/file/...`).
  final String path;

  /// Absolute fetch URL. Throws [FormatException] when [path] escapes the
  /// subscription's origin (a marker must never point elsewhere).
  Uri resolve(Uri subscriptionUri) {
    final resolved = subscriptionUri.resolve(path);
    if (resolved.scheme != subscriptionUri.scheme ||
        resolved.host != subscriptionUri.host ||
        resolved.port != subscriptionUri.port) {
      throw const FormatException(
        'file reference escapes its subscription origin',
      );
    }
    return resolved;
  }

  @override
  String toString() => 'OfficialFileRef(core: $coreId, tag: $tag)';
}

/// A file marker that could not become a config entry.
///
/// Carries no payload, URL, or token — only the stable identity (core/tag)
/// and a safe reason, so it is always loggable.
class OfficialFileError {
  const OfficialFileError({
    required this.coreId,
    required this.tag,
    required this.reason,
  });

  final String coreId;
  final String tag;
  final String reason;

  @override
  String toString() =>
      'OfficialFileError(core: $coreId, tag: $tag, reason: $reason)';
}

/// Extract file references from a subscription body.
///
/// [input] is the body AS FETCHED: markers are found directly in plain-text
/// bodies, or inside the base64 envelope after decoding (a base64 blob cannot
/// contain `#`, so the two cases never overlap). A malformed marker line is
/// skipped — an unresolvable reference must not break the configs that DID
/// parse. More than [maximumFileRefs] markers is a corrupt body.
List<OfficialFileRef> extractFileRefs(
  String input, {
  int maximumFileRefs = 64,
}) {
  final refs = <OfficialFileRef>[];
  void scan(String body) {
    for (final sourceLine in const LineSplitter().convert(body)) {
      var line = sourceLine.trimLeft();
      if (!line.startsWith('#')) continue;
      line = line.substring(1).trimLeft();
      if (!line.startsWith(_markerPrefix)) continue;
      final ref = _parseMarker(line.substring(_markerPrefix.length).trim());
      if (ref != null) {
        refs.add(ref);
        if (refs.length > maximumFileRefs) {
          throw const FormatException('subscription references too many files');
        }
      }
    }
  }

  scan(input);
  if (refs.isEmpty) {
    final decoded = _tryDecodeBase64(input);
    if (decoded != null) scan(decoded);
  }
  return List<OfficialFileRef>.unmodifiable(refs);
}

const _markerPrefix = 'zagros-file:';

OfficialFileRef? _parseMarker(String path) {
  if (path.isEmpty || path.length > 512 || path.contains('://')) return null;
  if (!path.startsWith('/sub/file/')) return null;
  // ['', 'sub', 'file', '<token>', '<core>', '<tag...>'] — the tag is
  // percent-encoded but may itself contain slashes, so it rejoins.
  final rest = path.split('/').sublist(1);
  if (rest.length < 5) return null;
  if (rest.any((s) => s.isEmpty || s == '.' || s == '..')) return null;
  final coreId = rest[3];
  final String tag;
  try {
    tag = Uri.decodeComponent(rest.sublist(4).join('/'));
  } on FormatException {
    return null;
  }
  if (coreId.isEmpty || coreId.length > 64 || tag.isEmpty || tag.length > 256) {
    return null;
  }
  return OfficialFileRef(coreId: coreId, tag: tag, path: path);
}

String? _tryDecodeBase64(String input) {
  final compact = input.replaceAll(RegExp(r'\s+'), '');
  if (compact.isEmpty || !RegExp(r'^[A-Za-z0-9+/_=-]+$').hasMatch(compact)) {
    return null;
  }
  try {
    final bytes = base64.decode(base64.normalize(compact));
    if (bytes.length > maximumConfigBytes) return null;
    return utf8.decode(bytes, allowMalformed: false);
  } on FormatException {
    return null;
  }
}
