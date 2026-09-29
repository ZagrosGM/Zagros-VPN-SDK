import '../models/config.dart';
import 'file_refs.dart';

enum OfficialProfileKind { subscription, manual }

class OfficialSubscriptionUsage {
  const OfficialSubscriptionUsage({
    required this.uploadBytes,
    required this.downloadBytes,
    required this.totalBytes,
    this.expiresAt,
  });

  final int uploadBytes;
  final int downloadBytes;
  final int totalBytes;
  final DateTime? expiresAt;

  int get usedBytes => uploadBytes + downloadBytes;

  int? get remainingBytes =>
      totalBytes <= 0 ? null : (totalBytes - usedBytes).clamp(0, totalBytes);
}

/// Where an entry's configuration material came from.
enum OfficialConfigSource {
  /// A share URI (or collection item) inside the subscription body.
  inline,

  /// A separately downloaded `zagros-file:` marker payload.
  file,
}

class OfficialConfigEntry {
  const OfficialConfigEntry({
    required this.id,
    required this.rawText,
    required this.normalized,
    this.source = OfficialConfigSource.inline,
    this.fileCoreId,
    this.fileTag,
  }) : assert(
          (source == OfficialConfigSource.file) ==
              (fileCoreId != null && fileTag != null),
          'file entries must carry their core and tag',
        );

  final String id;
  final String rawText;
  final NormalizedConfig normalized;

  /// File-backed entries render with a file badge and reconnect from the
  /// persisted payload (no re-download until the next refresh).
  final OfficialConfigSource source;

  /// Marker identity for file entries (`wireguard`/`wireguard`, ...): picks
  /// the re-parse routine on catalog load. Null for inline entries.
  final String? fileCoreId;
  final String? fileTag;

  @override
  String toString() =>
      'OfficialConfigEntry(id: $id, protocol: ${normalized.protocol}, raw: **redacted**)';
}

class OfficialProfile {
  OfficialProfile({
    required this.id,
    required this.name,
    required this.kind,
    required this.rawSource,
    required List<OfficialConfigEntry> configs,
    required this.createdAt,
    required this.updatedAt,
    this.subscriptionUri,
    this.lastRefreshedAt,
    this.etag,
    this.lastModified,
    this.usage,
    this.updateInterval,
    List<OfficialFileError>? fileErrors,
  })  : configs = List<OfficialConfigEntry>.unmodifiable(configs),
        fileErrors = List<OfficialFileError>.unmodifiable(
          fileErrors ?? const <OfficialFileError>[],
        );

  final String id;
  final String name;
  final OfficialProfileKind kind;
  final Uri? subscriptionUri;
  final String rawSource;
  final List<OfficialConfigEntry> configs;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime? lastRefreshedAt;
  final String? etag;
  final String? lastModified;
  final OfficialSubscriptionUsage? usage;
  final Duration? updateInterval;

  /// File markers that could not be turned into entries at the last refresh
  /// (download/parse failures). Transient: never persisted, recomputed on
  /// every refresh from the markers still present in the subscription body.
  final List<OfficialFileError> fileErrors;

  bool get isSubscription => kind == OfficialProfileKind.subscription;

  @override
  String toString() =>
      'OfficialProfile(id: $id, kind: $kind, configs: ${configs.length}, source: **redacted**)';
}

class OfficialProfileCatalog {
  OfficialProfileCatalog({
    required this.revision,
    required List<OfficialProfile> profiles,
  }) : profiles = List<OfficialProfile>.unmodifiable(profiles);

  factory OfficialProfileCatalog.empty() =>
      OfficialProfileCatalog(revision: 0, profiles: const <OfficialProfile>[]);

  final int revision;
  final List<OfficialProfile> profiles;

  OfficialProfile? byId(String id) {
    for (final profile in profiles) {
      if (profile.id == id) return profile;
    }
    return null;
  }
}

class ParsedOfficialConfig {
  const ParsedOfficialConfig({required this.rawText, required this.normalized});

  final String rawText;
  final NormalizedConfig normalized;
}

class OfficialSubscriptionDocument {
  OfficialSubscriptionDocument({
    required this.rawBody,
    required List<ParsedOfficialConfig> configs,
    required this.notModified,
    this.etag,
    this.lastModified,
    this.usage,
    this.updateInterval,
    List<OfficialFileRef>? fileRefs,
  })  : configs = List<ParsedOfficialConfig>.unmodifiable(configs),
        fileRefs = List<OfficialFileRef>.unmodifiable(
          fileRefs ?? const <OfficialFileRef>[],
        );

  final String rawBody;
  final List<ParsedOfficialConfig> configs;
  final bool notModified;
  final String? etag;
  final String? lastModified;
  final OfficialSubscriptionUsage? usage;
  final Duration? updateInterval;
  final List<OfficialFileRef> fileRefs;

  @override
  String toString() =>
      'OfficialSubscriptionDocument(configs: ${configs.length}, files: ${fileRefs.length}, body: **redacted**)';
}
