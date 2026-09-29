import 'dart:async';
import 'dart:math';

import '../crypto/encoding.dart';
import '../models/error.dart';
import '../parsers/openvpn_parser.dart';
import '../parsers/wireguard_parser.dart';
import '../policy/client_policy.dart';
import 'catalog_store.dart';
import 'device_id.dart';
import 'file_download_client.dart';
import 'file_refs.dart';
import 'models.dart';
import 'parser.dart';
import 'subscription_client.dart';

typedef OfficialClock = DateTime Function();
typedef OfficialIdGenerator = String Function();

/// One downloaded marker payload, ready to become an entry.
class _ResolvedFile {
  const _ResolvedFile({
    required this.config,
    required this.coreId,
    required this.tag,
  });

  final ParsedOfficialConfig config;
  final String coreId;
  final String tag;
}

class OfficialProfileRepository {
  OfficialProfileRepository({
    required this.policy,
    required this.store,
    required this.subscriptionClient,
    required this.deviceIdManager,
    this.parser = const OfficialConfigParser(),
    OfficialClock? clock,
    OfficialIdGenerator? idGenerator,
    OfficialFileDownloadClient? fileDownloadClient,
  })  : _files = fileDownloadClient ?? HttpOfficialFileDownloadClient(),
        _ownsFiles = fileDownloadClient == null,
        clock = clock ?? DateTime.now,
        idGenerator = idGenerator ?? _secureIdGenerator() {
    if (store.policy.mode != policy.mode) {
      throw ArgumentError('Official repository and store policies must match');
    }
  }

  final ClientPolicy policy;
  final SecureOfficialCatalogStore store;
  final OfficialSubscriptionClient subscriptionClient;
  final OfficialDeviceIdManager deviceIdManager;
  final OfficialConfigParser parser;
  final OfficialClock clock;
  final OfficialIdGenerator idGenerator;
  final OfficialFileDownloadClient _files;
  final bool _ownsFiles;

  Future<void> _tail = Future<void>.value();

  Future<OfficialProfileCatalog> load() => _exclusive(() async {
        _requirePersistence();
        return store.load();
      });

  Future<OfficialProfileCatalog> addManual({
    required String name,
    required String rawSource,
  }) =>
      _exclusive(() async {
        policy.require(ClientCapability.manualConfig);
        _requirePersistence();
        final normalizedName = _name(name);
        final parsed = parser.parse(rawSource);
        final catalog = await store.load();
        _requireProfileCapacity(catalog);
        final id = _newUniqueId(catalog);
        final now = clock().toUtc();
        final profile = OfficialProfile(
          id: id,
          name: normalizedName,
          kind: OfficialProfileKind.manual,
          rawSource: rawSource.trim(),
          configs: _entries(id, parsed),
          createdAt: now,
          updatedAt: now,
        );
        return _save(catalog, <OfficialProfile>[...catalog.profiles, profile]);
      });

  Future<OfficialProfileCatalog> addSubscription({
    required String name,
    required String url,
  }) =>
      _exclusive(() async {
        policy.require(ClientCapability.subscriptionImport);
        _requirePersistence();
        final normalizedName = _name(name);
        final uri = _uri(url);
        final catalog = await store.load();
        _requireProfileCapacity(catalog);
        final deviceId = await deviceIdManager.loadOrCreate();
        final document =
            await subscriptionClient.fetch(uri, deviceId: deviceId);
        final files = await _resolveFileEntries(uri, document, deviceId);
        if (document.notModified ||
            (document.configs.isEmpty && files.files.isEmpty)) {
          throw const ZagrosException(
            ZagrosErrorKind.malformedResponse,
            'New subscription returned no configurations',
          );
        }
        final id = _newUniqueId(catalog);
        final now = clock().toUtc();
        final profile = _subscriptionProfile(
          id: id,
          name: normalizedName,
          uri: uri,
          document: document,
          createdAt: now,
          updatedAt: now,
          lastRefreshedAt: now,
          files: files.files,
          fileErrors: files.errors,
        );
        return _save(catalog, <OfficialProfile>[...catalog.profiles, profile]);
      });

  Future<OfficialProfileCatalog> updateManual({
    required String profileId,
    required String name,
    required String rawSource,
  }) =>
      _exclusive(() async {
        policy.require(ClientCapability.manualConfig);
        _requirePersistence();
        final parsed = parser.parse(rawSource);
        final catalog = await store.load();
        final existing = _profile(catalog, profileId);
        if (existing.kind != OfficialProfileKind.manual) {
          throw const ZagrosException(
            ZagrosErrorKind.validation,
            'Profile is not a manual configuration',
          );
        }
        final updated = OfficialProfile(
          id: existing.id,
          name: _name(name),
          kind: existing.kind,
          rawSource: rawSource.trim(),
          configs: _entries(existing.id, parsed),
          createdAt: existing.createdAt,
          updatedAt: _nextTimestamp(existing),
        );
        return _replaceAndSave(catalog, updated);
      });

  Future<OfficialProfileCatalog> updateSubscription({
    required String profileId,
    required String name,
    required String url,
  }) =>
      _exclusive(() async {
        policy.require(ClientCapability.subscriptionImport);
        _requirePersistence();
        final catalog = await store.load();
        final existing = _profile(catalog, profileId);
        if (existing.kind != OfficialProfileKind.subscription) {
          throw const ZagrosException(
            ZagrosErrorKind.validation,
            'Profile is not a subscription',
          );
        }
        final normalizedName = _name(name);
        final uri = _uri(url);
        final sameUri = uri == existing.subscriptionUri;
        final deviceId = await deviceIdManager.loadOrCreate();
        final document = await subscriptionClient.fetch(
          uri,
          deviceId: deviceId,
          etag: sameUri ? existing.etag : null,
          lastModified: sameUri ? existing.lastModified : null,
        );
        if (document.notModified && !sameUri) {
          throw const ZagrosException(
            ZagrosErrorKind.malformedResponse,
            'Changed subscription returned no configurations',
          );
        }
        final now = _nextTimestamp(existing);
        final files = document.notModified
            ? null
            : await _resolveFileEntries(uri, document, deviceId);
        final updated = document.notModified
            ? _notModifiedProfile(
                existing: existing,
                name: normalizedName,
                uri: uri,
                document: document,
                now: now,
              )
            : _subscriptionProfile(
                id: existing.id,
                name: normalizedName,
                uri: uri,
                document: document,
                createdAt: existing.createdAt,
                updatedAt: now,
                lastRefreshedAt: now,
                files: files!.files,
                fileErrors: files.errors,
              );
        return _replaceAndSave(catalog, updated);
      });

  Future<OfficialProfileCatalog> refreshSubscription(String profileId) =>
      _exclusive(() async {
        policy.require(ClientCapability.subscriptionImport);
        _requirePersistence();
        final catalog = await store.load();
        final existing = _profile(catalog, profileId);
        final uri = existing.subscriptionUri;
        if (existing.kind != OfficialProfileKind.subscription || uri == null) {
          throw const ZagrosException(
            ZagrosErrorKind.validation,
            'Profile is not a subscription',
          );
        }
        final deviceId = await deviceIdManager.loadOrCreate();
        final document = await subscriptionClient.fetch(
          uri,
          deviceId: deviceId,
          etag: existing.etag,
          lastModified: existing.lastModified,
        );
        final now = _nextTimestamp(existing);
        final files = document.notModified
            ? null
            : await _resolveFileEntries(uri, document, deviceId);
        final updated = document.notModified
            ? _notModifiedProfile(
                existing: existing,
                name: existing.name,
                uri: uri,
                document: document,
                now: now,
              )
            : _subscriptionProfile(
                id: existing.id,
                name: existing.name,
                uri: uri,
                document: document,
                createdAt: existing.createdAt,
                updatedAt: now,
                lastRefreshedAt: now,
                files: files!.files,
                fileErrors: files.errors,
              );
        return _replaceAndSave(catalog, updated);
      });

  Future<OfficialProfileCatalog> rename({
    required String profileId,
    required String name,
  }) =>
      _exclusive(() async {
        _requirePersistence();
        final catalog = await store.load();
        final existing = _profile(catalog, profileId);
        _requireKind(existing.kind);
        final updated = OfficialProfile(
          id: existing.id,
          name: _name(name),
          kind: existing.kind,
          subscriptionUri: existing.subscriptionUri,
          rawSource: existing.rawSource,
          configs: existing.configs,
          createdAt: existing.createdAt,
          updatedAt: _nextTimestamp(existing),
          lastRefreshedAt: existing.lastRefreshedAt,
          etag: existing.etag,
          lastModified: existing.lastModified,
          usage: existing.usage,
          updateInterval: existing.updateInterval,
          fileErrors: existing.fileErrors,
        );
        return _replaceAndSave(catalog, updated);
      });

  Future<OfficialProfileCatalog> delete(String profileId) =>
      _exclusive(() async {
        _requirePersistence();
        final catalog = await store.load();
        final existing = _profile(catalog, profileId);
        _requireKind(existing.kind);
        return _save(
          catalog,
          catalog.profiles
              .where((profile) => profile.id != profileId)
              .toList(growable: false),
        );
      });

  void close() {
    subscriptionClient.close();
    if (_ownsFiles) _files.close();
  }

  Future<OfficialProfileCatalog> _save(
    OfficialProfileCatalog previous,
    List<OfficialProfile> profiles,
  ) async {
    final next = OfficialProfileCatalog(
      revision: previous.revision + 1,
      profiles: profiles,
    );
    await store.save(next);
    return next;
  }

  Future<OfficialProfileCatalog> _replaceAndSave(
    OfficialProfileCatalog catalog,
    OfficialProfile replacement,
  ) =>
      _save(
        catalog,
        catalog.profiles
            .map((profile) =>
                profile.id == replacement.id ? replacement : profile)
            .toList(growable: false),
      );

  OfficialProfile _subscriptionProfile({
    required String id,
    required String name,
    required Uri uri,
    required OfficialSubscriptionDocument document,
    required DateTime createdAt,
    required DateTime updatedAt,
    required DateTime lastRefreshedAt,
    List<_ResolvedFile> files = const <_ResolvedFile>[],
    List<OfficialFileError> fileErrors = const <OfficialFileError>[],
  }) {
    if ((document.configs.isEmpty && files.isEmpty) ||
        document.rawBody.isEmpty) {
      throw const ZagrosException(
        ZagrosErrorKind.malformedResponse,
        'Subscription returned no configurations',
      );
    }
    final entries = <OfficialConfigEntry>[..._entries(id, document.configs)];
    for (final file in files) {
      entries.add(OfficialConfigEntry(
        id: '$id.${entries.length}',
        rawText: file.config.rawText,
        normalized: file.config.normalized,
        source: OfficialConfigSource.file,
        fileCoreId: file.coreId,
        fileTag: file.tag,
      ));
    }
    return OfficialProfile(
      id: id,
      name: name,
      kind: OfficialProfileKind.subscription,
      subscriptionUri: uri,
      rawSource: document.rawBody,
      configs: entries,
      createdAt: createdAt,
      updatedAt: updatedAt,
      lastRefreshedAt: lastRefreshedAt,
      etag: document.etag,
      lastModified: document.lastModified,
      usage: document.usage,
      updateInterval: document.updateInterval,
      fileErrors: fileErrors,
    );
  }

  /// Download and parse this refresh's file markers.
  ///
  /// Files are ADDITIVE: one dead marker must never nuke the working URI
  /// configs, so every failure is collected into [OfficialFileError]s and
  /// reported on the profile instead of failing the refresh. WireGuard only
  /// in this phase — other file-backed cores need their own project (no
  /// native engine to connect them), so their markers are left alone.
  Future<
      ({
        List<_ResolvedFile> files,
        List<OfficialFileError> errors,
      })> _resolveFileEntries(
    Uri uri,
    OfficialSubscriptionDocument document,
    String deviceId,
  ) async {
    final resolved = <_ResolvedFile>[];
    final errors = <OfficialFileError>[];
    final candidates = document.fileRefs
        .where((ref) => ref.coreId.toLowerCase() == 'wireguard')
        .toList(growable: false);
    for (var index = 0; index < candidates.length; index += 1) {
      final ref = candidates[index];
      if (index >= maximumFilesPerRefresh) {
        errors.add(OfficialFileError(
          coreId: ref.coreId,
          tag: ref.tag,
          reason: 'too many file markers in one subscription',
        ));
        continue;
      }
      try {
        final content = await _files.fetchFile(
          subscriptionUri: uri,
          ref: ref,
          deviceId: deviceId,
        );
        resolved.add(_ResolvedFile(
          config: ParsedOfficialConfig(
            rawText: content,
            normalized: parseWireGuard(
              content,
              displayName: 'WireGuard \u00b7 ${ref.tag}',
            ),
          ),
          coreId: ref.coreId,
          tag: ref.tag,
        ));
      } on ZagrosException catch (error) {
        errors.add(OfficialFileError(
          coreId: ref.coreId,
          tag: ref.tag,
          reason: 'file download failed (${error.kind.name})',
        ));
      } on FormatException {
        errors.add(OfficialFileError(
          coreId: ref.coreId,
          tag: ref.tag,
          reason: 'file is not a valid WireGuard profile',
        ));
      } catch (_) {
        errors.add(OfficialFileError(
          coreId: ref.coreId,
          tag: ref.tag,
          reason: 'file could not be used',
        ));
      }
    }
    return (files: resolved, errors: errors);
  }

  OfficialProfile _notModifiedProfile({
    required OfficialProfile existing,
    required String name,
    required Uri uri,
    required OfficialSubscriptionDocument document,
    required DateTime now,
  }) =>
      OfficialProfile(
        id: existing.id,
        name: name,
        kind: existing.kind,
        subscriptionUri: uri,
        rawSource: existing.rawSource,
        configs: existing.configs,
        createdAt: existing.createdAt,
        updatedAt: existing.updatedAt,
        lastRefreshedAt: now,
        etag: document.etag ?? existing.etag,
        lastModified: document.lastModified ?? existing.lastModified,
        usage: document.usage ?? existing.usage,
        updateInterval: document.updateInterval ?? existing.updateInterval,
        fileErrors: existing.fileErrors,
      );

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

  OfficialProfile _profile(OfficialProfileCatalog catalog, String id) {
    final profile = catalog.byId(id);
    if (profile == null) {
      throw const ZagrosException(
        ZagrosErrorKind.validation,
        'Official profile was not found',
      );
    }
    return profile;
  }

  void _requirePersistence() =>
      policy.require(ClientCapability.rawConfigPersistence);

  void _requireProfileCapacity(OfficialProfileCatalog catalog) {
    if (catalog.profiles.length >= SecureOfficialCatalogStore.maximumProfiles) {
      throw const ZagrosException(
        ZagrosErrorKind.validation,
        'Official profile limit was reached',
      );
    }
  }

  void _requireKind(OfficialProfileKind kind) {
    policy.require(
      kind == OfficialProfileKind.subscription
          ? ClientCapability.subscriptionImport
          : ClientCapability.manualConfig,
    );
  }

  String _newUniqueId(OfficialProfileCatalog catalog) {
    for (var attempt = 0; attempt < 4; attempt += 1) {
      final candidate = idGenerator();
      if (RegExp(r'^[A-Za-z0-9_-]{8,128}$').hasMatch(candidate) &&
          catalog.byId(candidate) == null) {
        return candidate;
      }
    }
    throw const ZagrosException(
      ZagrosErrorKind.unknown,
      'Could not allocate an Official profile ID',
    );
  }

  DateTime _nextTimestamp(OfficialProfile profile) {
    var floor = profile.updatedAt.toUtc();
    final lastRefreshedAt = profile.lastRefreshedAt?.toUtc();
    if (lastRefreshedAt != null && lastRefreshedAt.isAfter(floor)) {
      floor = lastRefreshedAt;
    }
    final now = clock().toUtc();
    return now.isBefore(floor) ? floor : now;
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
      throw const ZagrosException(
        ZagrosErrorKind.validation,
        'Official profile name is invalid',
      );
    }
    return normalized;
  }

  Uri _uri(String value) {
    if (value.length > 2048) {
      throw const ZagrosException(
        ZagrosErrorKind.validation,
        'Subscription URL is invalid',
      );
    }
    final uri = Uri.tryParse(value.trim());
    if (uri == null || uri.hasFragment || uri.userInfo.isNotEmpty) {
      throw const ZagrosException(
        ZagrosErrorKind.validation,
        'Subscription URL is invalid',
      );
    }
    final loopback =
        uri.host == 'localhost' || uri.host == '127.0.0.1' || uri.host == '::1';
    if (uri.host.isEmpty ||
        uri.port < 1 ||
        uri.port > 65535 ||
        (uri.scheme != 'https' && !(loopback && uri.scheme == 'http'))) {
      throw const ZagrosException(
        ZagrosErrorKind.secureTransportRequired,
        'Subscription URL must use HTTPS',
      );
    }
    return uri;
  }

  Future<T> _exclusive<T>(Future<T> Function() action) async {
    final previous = _tail;
    final release = Completer<void>();
    _tail = release.future;
    await previous;
    try {
      return await action();
    } finally {
      release.complete();
    }
  }

  static OfficialIdGenerator _secureIdGenerator() {
    final random = Random.secure();
    return () =>
        base64UrlNoPadding(List<int>.generate(18, (_) => random.nextInt(256)));
  }
}
