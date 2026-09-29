import 'dart:convert';

import '../models/config.dart';
import '../parsers/json_yaml_parser.dart';
import '../parsers/openvpn_parser.dart';
import '../parsers/parser_limits.dart';
import '../parsers/uri_parser.dart';
import '../parsers/wireguard_parser.dart';
import 'file_refs.dart';
import 'models.dart';

class OfficialConfigParser {
  const OfficialConfigParser();

  List<ParsedOfficialConfig> parse(String input) =>
      _parse(input, allowBase64Envelope: true);

  /// File references (`zagros-file:` markers) in a subscription body.
  ///
  /// Envelope-aware like [parse]: plain bodies are scanned directly, a
  /// base64 envelope is decoded first. Throws [FormatException] when the
  /// body references more than [maximumFileRefs] files.
  List<OfficialFileRef> fileRefs(String input, {int maximumFileRefs = 64}) =>
      extractFileRefs(input, maximumFileRefs: maximumFileRefs);

  List<ParsedOfficialConfig> _parse(
    String input, {
    required bool allowBase64Envelope,
  }) {
    enforceTextLimit(input);
    final trimmed = input.trim();
    if (trimmed.isEmpty) {
      throw const FormatException('configuration source is empty');
    }

    if (_looksLikeWireGuard(trimmed)) {
      return <ParsedOfficialConfig>[
        ParsedOfficialConfig(
          rawText: trimmed,
          normalized: parseWireGuard(trimmed),
        ),
      ];
    }
    if (_looksLikeOpenVpn(trimmed)) {
      return <ParsedOfficialConfig>[
        ParsedOfficialConfig(
          rawText: trimmed,
          normalized: parseOpenVpn(trimmed),
        ),
      ];
    }
    if (trimmed.startsWith('{')) {
      return _fromCollection(trimmed, parseSingBox(trimmed));
    }
    if (RegExp(
      r'(^|\n)\s*proxies\s*:',
      caseSensitive: false,
    ).hasMatch(trimmed)) {
      return _fromCollection(trimmed, parseClash(trimmed));
    }

    final lines = _parseShareLines(trimmed);
    if (lines != null) return lines;

    // A comments-only body is a valid files-only subscription: the markers
    // live in `# zagros-file:` comment lines and the entries arrive via
    // download, so there are zero inline configs — not an error.
    if (_isCommentsOnly(trimmed)) {
      return const <ParsedOfficialConfig>[];
    }

    if (allowBase64Envelope) {
      final decoded = _tryDecodeBase64(trimmed);
      if (decoded != null) {
        return _parse(decoded, allowBase64Envelope: false);
      }
    }

    throw const FormatException('unsupported configuration source');
  }

  List<ParsedOfficialConfig> _fromCollection(
    String raw,
    List<NormalizedConfig> configs,
  ) {
    if (configs.isEmpty) {
      throw const FormatException('configuration collection is empty');
    }
    if (configs.length > maximumCollectionItems) {
      throw const FormatException('configuration contains too many items');
    }
    return List<ParsedOfficialConfig>.unmodifiable(
      configs.map(
        (config) => ParsedOfficialConfig(rawText: raw, normalized: config),
      ),
    );
  }

  List<ParsedOfficialConfig>? _parseShareLines(String input) {
    final configs = <ParsedOfficialConfig>[];
    final seen = <String>{};
    var foundNonComment = false;
    for (final sourceLine in const LineSplitter().convert(input)) {
      final line = sourceLine.trim();
      if (line.isEmpty || line.startsWith('#')) continue;
      foundNonComment = true;
      try {
        final config = parseShareUri(line);
        if (seen.add(line)) {
          configs.add(ParsedOfficialConfig(rawText: line, normalized: config));
        }
      } on FormatException {
        return null;
      }
    }
    if (!foundNonComment || configs.isEmpty) return null;
    if (configs.length > maximumCollectionItems) {
      throw const FormatException('configuration contains too many items');
    }
    return List<ParsedOfficialConfig>.unmodifiable(configs);
  }

  String? _tryDecodeBase64(String input) {
    final compact = input.replaceAll(RegExp(r'\s+'), '');
    if (compact.isEmpty ||
        compact.length > ((maximumConfigBytes + 2) ~/ 3) * 4 + 2 ||
        !RegExp(r'^[A-Za-z0-9+/_=-]+$').hasMatch(compact)) {
      return null;
    }
    try {
      final bytes = base64.decode(base64.normalize(compact));
      if (bytes.length > maximumConfigBytes) {
        throw const FormatException('configuration exceeds size limit');
      }
      return utf8.decode(bytes, allowMalformed: false);
    } on FormatException {
      return null;
    }
  }

  bool _isCommentsOnly(String input) {
    var seenComment = false;
    for (final sourceLine in const LineSplitter().convert(input)) {
      final line = sourceLine.trim();
      if (line.isEmpty) continue;
      if (!line.startsWith('#')) return false;
      seenComment = true;
    }
    return seenComment;
  }

  bool _looksLikeWireGuard(String input) =>
      RegExp(r'^\s*\[Interface\]', caseSensitive: false).hasMatch(input);

  bool _looksLikeOpenVpn(String input) => RegExp(
        r'(^|\n)\s*(client\s*$|remote\s+)',
        caseSensitive: false,
      ).hasMatch(input);
}
