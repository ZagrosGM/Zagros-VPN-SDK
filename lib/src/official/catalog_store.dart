import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../models/json.dart';
import '../parsers/parser_limits.dart';
import '../parsers/wireguard_parser.dart';
import '../policy/client_policy.dart';
import '../storage/secure_storage.dart';
import 'file_download_client.dart';
import 'models.dart';
import 'parser.dart';

class SecureOfficialCatalogStore {
  SecureOfficialCatalogStore({
    required this.policy,
    required this.storage,
    this.parser = const OfficialConfigParser(),
  });

  static const int maximumCatalogBytes = 4 * 1024 * 1024;
  static const int maximumProfiles = 128;
  static const int chunkBytes = 48 * 1024;
  static const String _manifestKey = 'zagros.official.catalog.manifest.v1';

  final ClientPolicy policy;
  final SecureValueStore storage;
  final OfficialConfigParser parser;

  Future<OfficialProfileCatalog> load() async {
    policy.require(ClientCapability.rawConfigPersistence);
    final manifestBytes = await storage.read(_manifestKey);
    if (manifestBytes == null) return OfficialProfileCatalog.empty();
    final manifest = _decodeObject(manifestBytes, name: 'catalog manifest');
    if (requiredInt(manifest, 'v') != 1) {
      throw const FormatException('unsupported Official catalog manifest');
    }
    final slot = requiredString(manifest, 'slot');
    final count = requiredInt(manifest, 'chunks');
    final expectedBytes = requiredInt(manifest, 'bytes');
    final expectedDigest = requiredString(manifest, 'sha256');
    final expectedRevision = requiredInt(manifest, 'revision');
    if ((slot != 'a' && slot != 'b') ||
        count < 1 ||
        count > (maximumCatalogBytes / chunkBytes).ceil() ||
        expectedBytes < 1 ||
        expectedBytes > maximumCatalogBytes ||
        expectedRevision < 0 ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(expectedDigest)) {
      throw const FormatException('invalid Official catalog manifest');
    }

    final builder = BytesBuilder(copy: false);
    var length = 0;
    for (var index = 0; index < count; index += 1) {
      final chunk = await storage.read(_chunkKey(slot, index));
      if (chunk == null || chunk.isEmpty || chunk.length > chunkBytes) {
        throw const FormatException('Official catalog chunk is unavailable');
      }
      length += chunk.length;
      if (length > maximumCatalogBytes) {
        throw const FormatException('Official catalog exceeds size limit');
      }
      builder.add(chunk);
    }
    final bytes = builder.takeBytes();
    if (bytes.length != expectedBytes ||
        await _digest(bytes) != expectedDigest) {
      throw const FormatException('Official catalog integrity check failed');
    }
    final catalog = _decodeCatalog(bytes);
    if (catalog.revision != expectedRevision) {
      throw const FormatException('Official catalog revision check failed');
    }
    return catalog;
  }

  Future<void> save(OfficialProfileCatalog catalog) async {
    policy.require(ClientCapability.rawConfigPersistence);
    _validateCatalog(catalog);
    final encoded = utf8.encode(jsonEncode(_catalogJson(catalog)));
    if (encoded.isEmpty || encoded.length > maximumCatalogBytes) {
      throw const FormatException('Official catalog exceeds size limit');
    }

    final currentBytes = await storage.read(_manifestKey);
    var currentSlot = 'b';
    var currentChunks = 0;
    if (currentBytes != null) {
      final current = _decodeObject(currentBytes, name: 'catalog manifest');
      currentSlot = requiredString(current, 'slot');
      currentChunks = requiredInt(current, 'chunks');
      if ((currentSlot != 'a' && currentSlot != 'b') ||
          currentChunks < 1 ||
          currentChunks > (maximumCatalogBytes / chunkBytes).ceil()) {
        throw const FormatException('invalid Official catalog manifest');
      }
    }
    final targetSlot = currentSlot == 'a' ? 'b' : 'a';
    final chunks = (encoded.length / chunkBytes).ceil();
    for (var index = 0; index < chunks; index += 1) {
      final start = index * chunkBytes;
      final candidateEnd = start + chunkBytes;
      final end = candidateEnd > encoded.length ? encoded.length : candidateEnd;
      await storage.write(
        _chunkKey(targetSlot, index),
        encoded.sublist(start, end),
      );
    }
    final manifest = utf8.encode(
      jsonEncode(<String, Object?>{
        'v': 1,
        'slot': targetSlot,
        'chunks': chunks,
        'bytes': encoded.length,
        'sha256': await _digest(encoded),
        'revision': catalog.revision,
      }),
    );
    await storage.write(_manifestKey, manifest);
    await _cleanupObsoleteSlot(currentSlot, currentChunks);
  }

  Future<void> _cleanupObsoleteSlot(String slot, int chunks) async {
    for (var index = 0; index < chunks; index += 1) {
      try {
        await storage.delete(_chunkKey(slot, index));
      } catch (_) {
        // The new manifest is already committed and readable. A later write to
        // this inactive slot replaces its referenced range; never invalidate
        // the committed catalog because protected-store cleanup was refused.
      }
    }
  }

  OfficialProfileCatalog _decodeCatalog(List<int> bytes) {
    final root = _decodeObject(bytes, name: 'Official catalog');
    if (requiredInt(root, 'v') != 1) {
      throw const FormatException('unsupported Official catalog');
    }
    final revision = requiredInt(root, 'revision');
    final sourceProfiles = root['profiles'];
    if (revision < 0 || sourceProfiles is! List<Object?>) {
      throw const FormatException('invalid Official catalog');
    }
    if (sourceProfiles.length > maximumProfiles) {
      throw const FormatException('Official catalog has too many profiles');
    }
    final profiles = <OfficialProfile>[];
    final ids = <String>{};
    for (final source in sourceProfiles) {
      final profile = _profileFromJson(objectMap(source, name: 'profile'));
      if (!ids.add(profile.id)) {
        throw const FormatException('duplicate Official profile ID');
      }
      profiles.add(profile);
    }
    return OfficialProfileCatalog(revision: revision, profiles: profiles);
  }

  OfficialProfile _profileFromJson(Map<String, Object?> json) {
    final id = _identifier(requiredString(json, 'id'));
    final name = _name(requiredString(json, 'name'));
    final kindName = requiredString(json, 'kind');
    final kind = switch (kindName) {
      'subscription' => OfficialProfileKind.subscription,
      'manual' => OfficialProfileKind.manual,
      _ => throw const FormatException('invalid Official profile kind'),
    };
    final rawSource = requiredString(json, 'raw_source');
    final parsed = parser.parse(rawSource);
    final fileEntries = _fileEntriesFromJson(
      json['files'],
      profileId: id,
      startIndex: parsed.length,
    );
    final uriText = optionalString(json, 'subscription_uri');
    final subscriptionUri = uriText == null ? null : _subscriptionUri(uriText);
    if ((kind == OfficialProfileKind.subscription) !=
        (subscriptionUri != null)) {
      throw const FormatException('invalid Official subscription source');
    }
    final createdAt = _date(json, 'created_at');
    final updatedAt = _date(json, 'updated_at');
    final lastRefreshedAt = _optionalDate(json, 'last_refreshed_at');
    final etag = _boundedOptional(json, 'etag', 512);
    final lastModified = _boundedOptional(json, 'last_modified', 512);
    final usage = _usageFromJson(json['usage']);
    final updateInterval = _duration(json['update_interval_seconds']);
    if (updatedAt.isBefore(createdAt) ||
        (lastRefreshedAt != null && lastRefreshedAt.isBefore(createdAt)) ||
        (kind == OfficialProfileKind.manual &&
            (lastRefreshedAt != null ||
                etag != null ||
                lastModified != null ||
                usage != null ||
                updateInterval != null))) {
      throw const FormatException('invalid Official profile metadata');
    }
    return OfficialProfile(
      id: id,
      name: name,
      kind: kind,
      subscriptionUri: subscriptionUri,
      rawSource: rawSource,
      configs: [..._entries(id, parsed), ...fileEntries],
      createdAt: createdAt,
      updatedAt: updatedAt,
      lastRefreshedAt: lastRefreshedAt,
      etag: etag,
      lastModified: lastModified,
      usage: usage,
      updateInterval: updateInterval,
    );
  }

  Map<String, Object?> _catalogJson(OfficialProfileCatalog catalog) =>
      <String, Object?>{
        'v': 1,
        'revision': catalog.revision,
        'profiles': catalog.profiles.map(_profileJson).toList(growable: false),
      };

  Map<String, Object?> _profileJson(
    OfficialProfile profile,
  ) =>
      <String, Object?>{
        'id': profile.id,
        'name': profile.name,
        'kind': profile.kind.name,
        'subscription_uri': profile.subscriptionUri?.toString(),
        'raw_source': profile.rawSource,
        'files': profile.configs
            .where((entry) => entry.source == OfficialConfigSource.file)
            .map((entry) => <String, Object?>{
                  'core': entry.fileCoreId,
                  'tag': entry.fileTag,
                  'content': entry.rawText,
                })
            .toList(growable: false),
        'created_at': profile.createdAt.toUtc().toIso8601String(),
        'updated_at': profile.updatedAt.toUtc().toIso8601String(),
        'last_refreshed_at': profile.lastRefreshedAt?.toUtc().toIso8601String(),
        'etag': profile.etag,
        'last_modified': profile.lastModified,
        'usage': profile.usage == null
            ? null
            : <String, Object?>{
                'upload': profile.usage!.uploadBytes,
                'download': profile.usage!.downloadBytes,
                'total': profile.usage!.totalBytes,
                'expires_at':
                    profile.usage!.expiresAt?.toUtc().toIso8601String(),
              },
        'update_interval_seconds': profile.updateInterval?.inSeconds,
      };

  void _validateCatalog(OfficialProfileCatalog catalog) {
    if (catalog.revision < 0 || catalog.profiles.length > maximumProfiles) {
      throw const FormatException('invalid Official catalog');
    }
    final ids = <String>{};
    for (final profile in catalog.profiles) {
      _identifier(profile.id);
      _name(profile.name);
      if (!ids.add(profile.id) || profile.configs.isEmpty) {
        throw const FormatException('invalid Official profile');
      }
      if (profile.rawSource.isEmpty ||
          utf8.encode(profile.rawSource).length > maximumConfigBytes) {
        throw const FormatException('invalid Official profile source');
      }
      if ((profile.kind == OfficialProfileKind.subscription) !=
          (profile.subscriptionUri != null)) {
        throw const FormatException('invalid Official subscription source');
      }
      if (profile.subscriptionUri != null) {
        _subscriptionUri(profile.subscriptionUri.toString());
      }
      if (profile.updatedAt.toUtc().isBefore(profile.createdAt.toUtc()) ||
          (profile.lastRefreshedAt != null &&
              profile.lastRefreshedAt!.toUtc().isBefore(
                    profile.createdAt.toUtc(),
                  )) ||
          (profile.kind == OfficialProfileKind.manual &&
              (profile.lastRefreshedAt != null ||
                  profile.etag != null ||
                  profile.lastModified != null ||
                  profile.usage != null ||
                  profile.updateInterval != null))) {
        throw const FormatException('invalid Official profile metadata');
      }
      _validateBoundedValue(profile.etag, name: 'etag', maximum: 512);
      _validateBoundedValue(
        profile.lastModified,
        name: 'last_modified',
        maximum: 512,
      );
      final usage = profile.usage;
      if (usage != null &&
          !_validUsage(
            usage.uploadBytes,
            usage.downloadBytes,
            usage.totalBytes,
          )) {
        throw const FormatException('invalid subscription usage');
      }
      final interval = profile.updateInterval?.inSeconds;
      if (interval != null && (interval < 3600 || interval > 7 * 24 * 3600)) {
        throw const FormatException('invalid subscription update interval');
      }
      final parsed = parser.parse(profile.rawSource);
      final fileEntries = profile.configs
          .where((entry) => entry.source == OfficialConfigSource.file)
          .toList(growable: false);
      if (parsed.length + fileEntries.length != profile.configs.length) {
        throw const FormatException('invalid Official profile configurations');
      }
      for (var index = 0; index < parsed.length; index += 1) {
        final entry = profile.configs[index];
        if (entry.id != '${profile.id}.$index' ||
            entry.rawText != parsed[index].rawText ||
            entry.normalized.protocol != parsed[index].normalized.protocol) {
          throw const FormatException(
            'invalid Official profile configurations',
          );
        }
      }
      _validateFileEntries(profile.id, fileEntries, startIndex: parsed.length);
    }
  }

  Map<String, Object?> _decodeObject(List<int> bytes, {required String name}) {
    if (bytes.isEmpty || bytes.length > maximumCatalogBytes) {
      throw FormatException('$name exceeds size limit');
    }
    final decoded = jsonDecode(utf8.decode(bytes, allowMalformed: false));
    enforceJsonShape(decoded);
    return objectMap(decoded, name: name);
  }

  List<OfficialConfigEntry> _entries(
    String profileId,
    List<ParsedOfficialConfig> parsed,
  ) =>
      List<OfficialConfigEntry>.generate(
        parsed.length,
        (index) => OfficialConfigEntry(
          id: '$profileId.$index',
          rawText: parsed[index].rawText,
          normalized: parsed[index].normalized,
        ),
        growable: false,
      );

  /// File entries persisted by [_profileJson].
  ///
  /// Corrupt items are SKIPPED, never fatal: the markers stay in raw_source,
  /// so the next refresh re-downloads whatever load drops. A client that
  /// predates files ignores the whole `files` key and shows no file entries
  /// until it refreshes.
  List<OfficialConfigEntry> _fileEntriesFromJson(
    Object? source, {
    required String profileId,
    required int startIndex,
  }) {
    if (source == null) return const <OfficialConfigEntry>[];
    if (source is! List<Object?>) {
      throw const FormatException('invalid Official profile files');
    }
    final entries = <OfficialConfigEntry>[];
    var totalBytes = 0;
    for (final item in source) {
      if (entries.length >= maximumFilesPerRefresh) break;
      if (item is! Map<Object?, Object?>) continue;
      final core = item['core'];
      final tag = item['tag'];
      final content = item['content'];
      if (core is! String || tag is! String || content is! String) continue;
      if (core.isEmpty ||
          core.length > 64 ||
          tag.isEmpty ||
          tag.length > 256) {
        continue;
      }
      if (content.isEmpty || content.length > maximumFileBytes) continue;
      totalBytes += utf8.encode(content).length;
      if (totalBytes > maximumConfigBytes) break;
      // WireGuard only in this phase; other persisted cores are left for
      // the client version that writes them (refresh re-resolves anyway).
      if (core.toLowerCase() != 'wireguard') continue;
      try {
        entries.add(OfficialConfigEntry(
          id: '$profileId.${startIndex + entries.length}',
          rawText: content,
          normalized:
              parseWireGuard(content, displayName: 'WireGuard \u00b7 $tag'),
          source: OfficialConfigSource.file,
          fileCoreId: core,
          fileTag: tag,
        ));
      } on FormatException {
        continue;
      }
    }
    return List<OfficialConfigEntry>.unmodifiable(entries);
  }

  void _validateFileEntries(
    String profileId,
    List<OfficialConfigEntry> entries, {
    required int startIndex,
  }) {
    if (entries.length > maximumFilesPerRefresh) {
      throw const FormatException('Official profile has too many files');
    }
    var totalBytes = 0;
    for (var offset = 0; offset < entries.length; offset += 1) {
      final entry = entries[offset];
      final core = entry.fileCoreId;
      final tag = entry.fileTag;
      if (entry.id != '$profileId.${startIndex + offset}' ||
          core == null ||
          core.isEmpty ||
          core.length > 64 ||
          tag == null ||
          tag.isEmpty ||
          tag.length > 256 ||
          entry.rawText.isEmpty ||
          entry.rawText.length > maximumFileBytes) {
        throw const FormatException('invalid Official profile file');
      }
      totalBytes += utf8.encode(entry.rawText).length;
      if (totalBytes > maximumConfigBytes) {
        throw const FormatException('Official profile files are too large');
      }
      // This client only writes WireGuard files; anything else fails
      // closed — saving what load cannot rebuild would corrupt the catalog.
      if (core.toLowerCase() != 'wireguard' ||
          !_fileProtocolMatches(entry)) {
        throw const FormatException('invalid Official profile file');
      }
    }
  }

  bool _fileProtocolMatches(OfficialConfigEntry entry) {
    try {
      return parseWireGuard(entry.rawText).protocol ==
          entry.normalized.protocol;
    } on FormatException {
      return false;
    }
  }

  OfficialSubscriptionUsage? _usageFromJson(Object? source) {
    if (source == null) return null;
    final json = objectMap(source, name: 'subscription usage');
    final upload = requiredInt(json, 'upload');
    final download = requiredInt(json, 'download');
    final total = requiredInt(json, 'total');
    if (!_validUsage(upload, download, total)) {
      throw const FormatException('invalid subscription usage');
    }
    return OfficialSubscriptionUsage(
      uploadBytes: upload,
      downloadBytes: download,
      totalBytes: total,
      expiresAt: _optionalDate(json, 'expires_at'),
    );
  }

  Duration? _duration(Object? source) {
    if (source == null) return null;
    if (source is! int || source < 3600 || source > 7 * 24 * 3600) {
      throw const FormatException('invalid subscription update interval');
    }
    return Duration(seconds: source);
  }

  DateTime _date(Map<String, Object?> json, String key) {
    final value = DateTime.tryParse(requiredString(json, key));
    if (value == null) throw FormatException('invalid $key');
    return value.toUtc();
  }

  DateTime? _optionalDate(Map<String, Object?> json, String key) {
    final source = optionalString(json, key);
    if (source == null) return null;
    final value = DateTime.tryParse(source);
    if (value == null) throw FormatException('invalid $key');
    return value.toUtc();
  }

  String? _boundedOptional(Map<String, Object?> json, String key, int maximum) {
    final value = optionalString(json, key);
    if (value == null) return null;
    _validateBoundedValue(value, name: key, maximum: maximum);
    return value;
  }

  void _validateBoundedValue(
    String? value, {
    required String name,
    required int maximum,
  }) {
    if (value == null) return;
    if (value.isEmpty ||
        value.length > maximum ||
        value.codeUnits.any((code) => code < 32 || code > 126)) {
      throw FormatException('invalid $name');
    }
  }

  bool _validUsage(int upload, int download, int total) =>
      upload >= 0 &&
      download >= 0 &&
      total >= 0 &&
      upload <= 9223372036854775807 &&
      download <= 9223372036854775807 &&
      total <= 9223372036854775807;

  String _identifier(String value) {
    if (!RegExp(r'^[A-Za-z0-9_-]{8,128}$').hasMatch(value)) {
      throw const FormatException('invalid Official profile ID');
    }
    return value;
  }

  String _name(String value) {
    final normalized = value.trim();
    if (normalized.isEmpty ||
        normalized.length > 128 ||
        normalized.runes.any(
          (rune) =>
              rune < 32 ||
              (rune >= 127 && rune <= 159) ||
              rune == 0x2028 ||
              rune == 0x2029,
        )) {
      throw const FormatException('invalid Official profile name');
    }
    return normalized;
  }

  Uri _subscriptionUri(String value) {
    if (value.length > 2048) {
      throw const FormatException('invalid Official subscription source');
    }
    final uri = Uri.tryParse(value);
    if (uri == null) {
      throw const FormatException('invalid Official subscription source');
    }
    final loopback =
        uri.host == 'localhost' || uri.host == '127.0.0.1' || uri.host == '::1';
    if (uri.host.isEmpty ||
        uri.port < 1 ||
        uri.port > 65535 ||
        uri.userInfo.isNotEmpty ||
        uri.hasFragment ||
        (uri.scheme != 'https' && !(loopback && uri.scheme == 'http'))) {
      throw const FormatException('invalid Official subscription source');
    }
    return uri;
  }

  static String _chunkKey(String slot, int index) =>
      'zagros.official.catalog.$slot.$index.v1';

  Future<String> _digest(List<int> bytes) async {
    final hash = await Sha256().hash(bytes);
    return hash.bytes
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
  }
}
