import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

const _wgConf = '''[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.9.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=
Endpoint = 203.0.113.7:51820
AllowedIPs = 0.0.0.0/0
''';

const _link = 'ss://YWVzLTI1Ni1nY206c2VjcmV0@example:8388#one';
const _markerWg = '# zagros-file: /sub/file/TOKEN0123456789abcdef0123456789/wireguard/wg0';
const _markerOvpn =
    '# zagros-file: /sub/file/TOKEN0123456789abcdef0123456789/openvpn/ovpn0';

class _MemoryStore implements SecureValueStore {
  final Map<String, List<int>> values = <String, List<int>>{};

  @override
  Future<void> delete(String key) async => values.remove(key);

  @override
  Future<List<int>?> read(String key) async {
    final value = values[key];
    return value == null ? null : List<int>.of(value);
  }

  @override
  Future<void> write(String key, List<int> value) async {
    values[key] = List<int>.of(value);
  }
}

class _FakeSubscriptions implements OfficialSubscriptionClient {
  _FakeSubscriptions(this.document);

  OfficialSubscriptionDocument document;

  @override
  Future<OfficialSubscriptionDocument> fetch(
    Uri uri, {
    required String deviceId,
    String? etag,
    String? lastModified,
  }) async =>
      document;

  @override
  void close() {}
}

class _FakeFiles implements OfficialFileDownloadClient {
  String? payload = _wgConf;
  Object? nextError;
  final List<OfficialFileRef> calls = <OfficialFileRef>[];
  bool closed = false;

  @override
  Future<String> fetchFile({
    required Uri subscriptionUri,
    required OfficialFileRef ref,
    required String deviceId,
  }) async {
    calls.add(ref);
    final error = nextError;
    nextError = null;
    if (error != null) throw error;
    final body = payload;
    if (body == null) {
      throw const ZagrosException(
        ZagrosErrorKind.validation,
        'File download was rejected',
      );
    }
    return body;
  }

  @override
  void close() => closed = true;
}

OfficialSubscriptionDocument _doc(String rawBody) {
  const parser = OfficialConfigParser();
  return OfficialSubscriptionDocument(
    rawBody: rawBody,
    configs: parser.parse(rawBody),
    fileRefs: parser.fileRefs(rawBody),
    notModified: false,
  );
}

OfficialProfileRepository _repository(
  _MemoryStore storage,
  _FakeSubscriptions subscriptions,
  _FakeFiles files,
) =>
    OfficialProfileRepository(
      policy: const ClientPolicy.official(),
      store: SecureOfficialCatalogStore(
        policy: const ClientPolicy.official(),
        storage: storage,
      ),
      subscriptionClient: subscriptions,
      deviceIdManager: OfficialDeviceIdManager(storage),
      fileDownloadClient: files,
      idGenerator: () => 'profile_testfile_01',
      clock: () => DateTime.utc(2026, 9, 9, 12),
    );

void main() {
  group('HttpOfficialFileDownloadClient', () {
    const ref = OfficialFileRef(
      coreId: 'wireguard',
      tag: 'wg0',
      path: '/sub/file/TOKEN/wireguard/wg0',
    );
    final subUri = Uri.parse('https://panel.example:8443/sub/TOKEN');

    test('downloads from the resolved same-origin URL', () async {
      Uri? seen;
      String? seenDevice;
      final client = HttpOfficialFileDownloadClient(
        client: MockClient((request) async {
          seen = request.url;
          seenDevice = request.headers['x-device-id'];
          return http.Response(_wgConf, 200);
        }),
      );
      final body = await client.fetchFile(
        subscriptionUri: subUri,
        ref: ref,
        deviceId: 'device-01',
      );
      expect(body, _wgConf);
      expect(
        seen.toString(),
        'https://panel.example:8443/sub/file/TOKEN/wireguard/wg0',
      );
      expect(seenDevice, 'device-01');
      client.close();
    });

    test('maps failure statuses without following redirects', () async {
      Future<ZagrosErrorKind> kindFor(int status) async {
        final client = HttpOfficialFileDownloadClient(
          client: MockClient((_) async => http.Response('no', status)),
        );
        try {
          await client.fetchFile(
            subscriptionUri: subUri,
            ref: ref,
            deviceId: 'device-01',
          );
          fail('expected a download failure');
        } on ZagrosException catch (error) {
          return error.kind;
        } finally {
          client.close();
        }
      }

      expect(await kindFor(404), ZagrosErrorKind.validation);
      expect(await kindFor(302), ZagrosErrorKind.unknown);
      expect(await kindFor(500), ZagrosErrorKind.transport);
    });

    test('enforces the byte cap while streaming', () async {
      final client = HttpOfficialFileDownloadClient(
        maximumResponseBytes: 1024,
        client: MockClient((_) async => http.Response('x' * 2000, 200)),
      );
      try {
        await expectLater(
          client.fetchFile(
            subscriptionUri: subUri,
            ref: ref,
            deviceId: 'device-01',
          ),
          throwsA(
            isA<ZagrosException>().having(
              (e) => e.kind,
              'kind',
              ZagrosErrorKind.malformedResponse,
            ),
          ),
        );
      } finally {
        client.close();
      }
    });

    test('rejects empty payloads and escaping references', () async {
      final empty = HttpOfficialFileDownloadClient(
        client: MockClient((_) async => http.Response('  \n ', 200)),
      );
      await expectLater(
        empty.fetchFile(
          subscriptionUri: subUri,
          ref: ref,
          deviceId: 'device-01',
        ),
        throwsA(isA<ZagrosException>()),
      );
      empty.close();

      const evil = OfficialFileRef(
        coreId: 'wireguard',
        tag: 'x',
        path: 'https://evil.example/z',
      );
      final client = HttpOfficialFileDownloadClient(
        client: MockClient((_) async => http.Response('x', 200)),
      );
      await expectLater(
        client.fetchFile(
          subscriptionUri: subUri,
          ref: evil,
          deviceId: 'device-01',
        ),
        throwsFormatException,
      );
      client.close();
    });

    test('constructor enforces bounded settings', () {
      expect(
        () => HttpOfficialFileDownloadClient(timeout: Duration.zero),
        throwsArgumentError,
      );
      expect(
        () => HttpOfficialFileDownloadClient(
          maximumResponseBytes: maximumFileBytes + 1,
        ),
        throwsArgumentError,
      );
    });
  });

  group('Repository file merge', () {
    late _MemoryStore storage;
    late _FakeSubscriptions subscriptions;
    late _FakeFiles files;
    late OfficialProfileRepository repository;

    setUp(() {
      storage = _MemoryStore();
      subscriptions = _FakeSubscriptions(_doc('$_link\n$_markerWg\n'));
      files = _FakeFiles();
      repository = _repository(storage, subscriptions, files);
    });

    test('appends a WireGuard file entry after the inline configs', () async {
      final catalog = await repository.addSubscription(
        name: 'wg test',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      final profile = catalog.profiles.single;
      expect(profile.configs, hasLength(2));
      final inline = profile.configs[0];
      final file = profile.configs[1];
      expect(inline.source, OfficialConfigSource.inline);
      expect(inline.id, '${profile.id}.0');
      expect(file.source, OfficialConfigSource.file);
      expect(file.id, '${profile.id}.1');
      expect(file.normalized.protocol, 'wireguard');
      expect(file.normalized.engine, 'wireguard');
      expect(file.fileCoreId, 'wireguard');
      expect(file.fileTag, 'wg0');
      expect(file.normalized.displayName, contains('wg0'));
      expect(profile.fileErrors, isEmpty);
      expect(files.calls, hasLength(1));
    });

    test('a dead marker never nukes the working configs', () async {
      files.nextError = const ZagrosException(
        ZagrosErrorKind.transport,
        'File download was rejected',
      );
      final catalog = await repository.addSubscription(
        name: 'wg test',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      final profile = catalog.profiles.single;
      expect(profile.configs, hasLength(1));
      expect(profile.configs.single.source, OfficialConfigSource.inline);
      expect(profile.fileErrors, hasLength(1));
      expect(profile.fileErrors.single.coreId, 'wireguard');
      expect(profile.fileErrors.single.tag, 'wg0');
      expect(profile.fileErrors.single.reason, contains('download failed'));
    });

    test('a corrupt payload is reported, not stored', () async {
      files.payload = 'not a wireguard profile';
      final catalog = await repository.addSubscription(
        name: 'wg test',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      final profile = catalog.profiles.single;
      expect(profile.configs, hasLength(1));
      expect(profile.fileErrors, hasLength(1));
      expect(
        profile.fileErrors.single.reason,
        'file is not a valid WireGuard profile',
      );
    });

    test('non-WireGuard markers are left for their own project', () async {
      subscriptions.document = _doc('$_link\n$_markerOvpn\n');
      final catalog = await repository.addSubscription(
        name: 'ovpn untouched',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      final profile = catalog.profiles.single;
      expect(profile.configs, hasLength(1));
      expect(profile.fileErrors, isEmpty);
      expect(files.calls, isEmpty);
    });

    test('a files-only subscription yields a file-only profile', () async {
      subscriptions.document = _doc('$_markerWg\n# served by the panel\n');
      final catalog = await repository.addSubscription(
        name: 'files only',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      final profile = catalog.profiles.single;
      expect(profile.configs, hasLength(1));
      expect(profile.configs.single.source, OfficialConfigSource.file);
      expect(profile.fileErrors, isEmpty);
    });

    test('a 304 refresh keeps the persisted file entries', () async {
      var catalog = await repository.addSubscription(
        name: 'wg test',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      final profileId = catalog.profiles.single.id;
      subscriptions.document = OfficialSubscriptionDocument(
        rawBody: '',
        configs: const [],
        notModified: true,
      );
      catalog = await repository.refreshSubscription(profileId);
      final profile = catalog.profiles.single;
      expect(profile.configs, hasLength(2));
      expect(profile.configs[1].source, OfficialConfigSource.file);
      expect(profile.configs[1].normalized.protocol, 'wireguard');
      // No re-download on a 304: the single call came from the add above.
      expect(files.calls, hasLength(1));
    });

    test('markers past the per-refresh cap are reported', () async {
      final markers = List<String>.generate(
        maximumFilesPerRefresh + 1,
        (i) =>
            '# zagros-file: /sub/file/TOKEN0123456789abcdef0123456789/wireguard/vpn$i',
      ).join('\n');
      subscriptions.document = _doc('$_link\n$markers\n');
      final catalog = await repository.addSubscription(
        name: 'many files',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      final profile = catalog.profiles.single;
      expect(profile.configs, hasLength(1 + maximumFilesPerRefresh));
      expect(profile.fileErrors, hasLength(1));
      expect(profile.fileErrors.single.reason, contains('too many'));
    });
  });

  group('Catalog file persistence', () {
    test('file entries survive a save/load round trip', () async {
      final storage = _MemoryStore();
      final repository = _repository(
        storage,
        _FakeSubscriptions(_doc('$_link\n$_markerWg\n')),
        _FakeFiles(),
      );
      final saved = await repository.addSubscription(
        name: 'persist me',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      final store = SecureOfficialCatalogStore(
        policy: const ClientPolicy.official(),
        storage: storage,
      );
      final loaded = await store.load();
      expect(loaded.revision, saved.revision);
      final profile = loaded.profiles.single;
      expect(profile.configs, hasLength(2));
      final file = profile.configs[1];
      expect(file.source, OfficialConfigSource.file);
      expect(file.normalized.protocol, 'wireguard');
      expect(file.fileCoreId, 'wireguard');
      expect(file.fileTag, 'wg0');
      expect(file.rawText, _wgConf);
      // Transient errors are never persisted.
      expect(profile.fileErrors, isEmpty);
    });

    test('a corrupt persisted file is dropped, never fatal', () async {
      final storage = _MemoryStore();
      final repository = _repository(
        storage,
        _FakeSubscriptions(_doc('$_link\n$_markerWg\n')),
        _FakeFiles(),
      );
      await repository.addSubscription(
        name: 'tamper me',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      await _tamperFiles(storage, 'not a wireguard profile');
      final store = SecureOfficialCatalogStore(
        policy: const ClientPolicy.official(),
        storage: storage,
      );
      final loaded = await store.load();
      final profile = loaded.profiles.single;
      expect(profile.configs, hasLength(1));
      expect(profile.configs.single.source, OfficialConfigSource.inline);
    });

    test('a malformed files key fails closed', () async {
      final storage = _MemoryStore();
      final repository = _repository(
        storage,
        _FakeSubscriptions(_doc('$_link\n$_markerWg\n')),
        _FakeFiles(),
      );
      await repository.addSubscription(
        name: 'tamper me',
        url: 'https://panel.example:8443/sub/TOKEN0123456789abcdef0123456789',
      );
      await _tamperFiles(storage, 42);
      final store = SecureOfficialCatalogStore(
        policy: const ClientPolicy.official(),
        storage: storage,
      );
      await expectLater(store.load(), throwsFormatException);
    });
  });

  group('OfficialConfigParser comments-only', () {
    test('comments-only bodies yield zero configs, not an error', () {
      const parser = OfficialConfigParser();
      expect(parser.parse('# zagros-file: /sub/file/T/wireguard/wg0\n# note\n'),
          isEmpty);
      expect(() => parser.parse('not a configuration'), throwsFormatException);
    });
  });
}

/// Rewrites the stored catalog with [replacement] as the first file's
/// content, keeping manifest/chunk/digest framing valid.
Future<void> _tamperFiles(_MemoryStore storage, Object? replacement) async {
  const manifestKey = 'zagros.official.catalog.manifest.v1';
  final manifestBytes = await storage.read(manifestKey);
  final manifest =
      jsonDecode(utf8.decode(manifestBytes!)) as Map<String, Object?>;
  final slot = manifest['slot'] as String;
  final chunks = manifest['chunks'] as int;
  final builder = BytesBuilder(copy: false);
  for (var index = 0; index < chunks; index += 1) {
    builder.add(
        (await storage.read('zagros.official.catalog.$slot.$index.v1'))!);
  }
  final catalog =
      jsonDecode(utf8.decode(builder.takeBytes())) as Map<String, Object?>;
  final profiles = catalog['profiles'] as List<Object?>;
  final profile = profiles.single as Map<String, Object?>;
  if (replacement is String) {
    final files = profile['files'] as List<Object?>;
    (files.single as Map<String, Object?>)['content'] = replacement;
  } else {
    profile['files'] = replacement;
  }
  final encoded = utf8.encode(jsonEncode(catalog));
  const chunkBytes = 48 * 1024;
  final count = (encoded.length / chunkBytes).ceil();
  for (var index = 0; index < count; index += 1) {
    final start = index * chunkBytes;
    final end =
        start + chunkBytes > encoded.length ? encoded.length : start + chunkBytes;
    await storage.write(
      'zagros.official.catalog.$slot.$index.v1',
      encoded.sublist(start, end),
    );
  }
  final digest = await Sha256().hash(encoded);
  final hex = digest.bytes
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join();
  await storage.write(
    manifestKey,
    utf8.encode(jsonEncode(<String, Object?>{
      'v': 1,
      'slot': slot,
      'chunks': count,
      'bytes': encoded.length,
      'sha256': hex,
      'revision': manifest['revision'],
    })),
  );
}
