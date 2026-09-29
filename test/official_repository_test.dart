import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

const _firstLink =
    'vless://00000000-0000-0000-0000-000000000001@vpn.example:443?security=tls&type=tcp#Primary';
const _secondLink =
    'trojan://secret@backup.example:443?security=tls&type=tcp#Backup';

class MemorySecureValueStore implements SecureValueStore {
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

class SubscriptionCall {
  const SubscriptionCall(this.uri, this.deviceId, this.etag, this.lastModified);

  final Uri uri;
  final String deviceId;
  final String? etag;
  final String? lastModified;
}

class FakeSubscriptionClient implements OfficialSubscriptionClient {
  FakeSubscriptionClient(this.document);

  OfficialSubscriptionDocument document;
  Object? nextError;
  final List<SubscriptionCall> calls = <SubscriptionCall>[];
  bool closed = false;

  @override
  Future<OfficialSubscriptionDocument> fetch(
    Uri uri, {
    required String deviceId,
    String? etag,
    String? lastModified,
  }) async {
    calls.add(SubscriptionCall(uri, deviceId, etag, lastModified));
    final error = nextError;
    nextError = null;
    if (error != null) throw error;
    return document;
  }

  @override
  void close() => closed = true;
}

void main() {
  group('Official repository CRUD', () {
    late MemorySecureValueStore storage;
    late FakeSubscriptionClient subscriptions;
    late OfficialProfileRepository repository;
    var id = 0;
    var tick = 0;

    setUp(() {
      id = 0;
      tick = 0;
      storage = MemorySecureValueStore();
      subscriptions =
          FakeSubscriptionClient(_document(_firstLink, etag: '"v1"'));
      repository = OfficialProfileRepository(
        policy: const ClientPolicy.official(),
        store: SecureOfficialCatalogStore(
          policy: const ClientPolicy.official(),
          storage: storage,
        ),
        subscriptionClient: subscriptions,
        deviceIdManager: OfficialDeviceIdManager(storage),
        idGenerator: () => 'profile_${++id}_secure',
        clock: () => DateTime.utc(2026, 9, 7, 12, tick++),
      );
    });

    test('manual add, edit, rename, and delete persist normalized models',
        () async {
      var catalog =
          await repository.addManual(name: ' Manual ', rawSource: _firstLink);
      expect(catalog.revision, 1);
      expect(catalog.profiles.single.name, 'Manual');
      expect(
          catalog.profiles.single.configs.single.normalized.protocol, 'vless');
      final profileId = catalog.profiles.single.id;

      catalog = await repository.updateManual(
        profileId: profileId,
        name: 'Updated',
        rawSource: _secondLink,
      );
      expect(catalog.revision, 2);
      expect(
          catalog.profiles.single.configs.single.normalized.protocol, 'trojan');

      catalog = await repository.rename(profileId: profileId, name: 'Renamed');
      expect(catalog.revision, 3);
      expect(catalog.profiles.single.name, 'Renamed');

      final reloaded = await repository.load();
      expect(reloaded.profiles.single.name, 'Renamed');
      expect(reloaded.profiles.single.configs.single.normalized.protocol,
          'trojan');

      catalog = await repository.delete(profileId);
      expect(catalog.revision, 4);
      expect(catalog.profiles, isEmpty);
      expect((await repository.load()).profiles, isEmpty);
    });

    test('subscription add and refresh use stable identity and validators',
        () async {
      var catalog = await repository.addSubscription(
        name: 'Subscription',
        url: 'https://panel.example/sub/token',
      );
      final profile = catalog.profiles.single;
      expect(profile.etag, '"v1"');
      expect(profile.configs.single.normalized.protocol, 'vless');
      expect(subscriptions.calls.single.deviceId, startsWith('zg_'));

      subscriptions.document = _document(_secondLink, etag: '"v2"');
      catalog = await repository.refreshSubscription(profile.id);
      expect(catalog.revision, 2);
      expect(catalog.profiles.single.etag, '"v2"');
      expect(
          catalog.profiles.single.configs.single.normalized.protocol, 'trojan');
      expect(subscriptions.calls.last.etag, '"v1"');
      expect(
        subscriptions.calls.last.deviceId,
        subscriptions.calls.first.deviceId,
      );

      subscriptions.document = OfficialSubscriptionDocument(
        rawBody: '',
        configs: const <ParsedOfficialConfig>[],
        notModified: true,
        etag: '"v2"',
      );
      final beforeUpdate = catalog.profiles.single.updatedAt;
      catalog = await repository.refreshSubscription(profile.id);
      expect(catalog.revision, 3);
      expect(catalog.profiles.single.rawSource, _secondLink);
      expect(catalog.profiles.single.updatedAt, beforeUpdate);
      expect(catalog.profiles.single.lastRefreshedAt, isNotNull);
    });

    test('changed URL rejects unsolicited 304 and invalid name before fetch',
        () async {
      final catalog = await repository.addSubscription(
        name: 'Subscription',
        url: 'https://panel.example/sub/token',
      );
      final profile = catalog.profiles.single;
      expect(subscriptions.calls, hasLength(1));

      await expectLater(
        repository.updateSubscription(
          profileId: profile.id,
          name: 'Invalid\nName',
          url: 'https://panel.example/sub/token',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.validation,
          ),
        ),
      );
      expect(subscriptions.calls, hasLength(1));

      subscriptions.document = OfficialSubscriptionDocument(
        rawBody: '',
        configs: const <ParsedOfficialConfig>[],
        notModified: true,
      );
      await expectLater(
        repository.updateSubscription(
          profileId: profile.id,
          name: 'Subscription',
          url: 'https://panel.example/other/token',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.malformedResponse,
          ),
        ),
      );
      final reloaded = await repository.load();
      expect(reloaded.revision, catalog.revision);
      expect(reloaded.profiles.single.subscriptionUri, profile.subscriptionUri);
    });

    test('failed refresh preserves the prior readable catalog', () async {
      final catalog = await repository.addSubscription(
        name: 'Subscription',
        url: 'https://panel.example/sub/token',
      );
      final original = catalog.profiles.single;
      subscriptions.nextError = const ZagrosTransportException('offline');

      await expectLater(
        repository.refreshSubscription(original.id),
        throwsA(isA<ZagrosTransportException>()),
      );

      final reloaded = await repository.load();
      expect(reloaded.revision, catalog.revision);
      expect(reloaded.profiles.single.rawSource, original.rawSource);
      expect(reloaded.profiles.single.etag, original.etag);
    });

    test('validates URL and serializes concurrent mutations', () async {
      await expectLater(
        repository.addSubscription(
          name: 'Bad',
          url: 'http://panel.example/sub',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.secureTransportRequired,
          ),
        ),
      );
      await expectLater(
        repository.addSubscription(
          name: 'Bad port',
          url: 'https://panel.example:99999/sub',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.secureTransportRequired,
          ),
        ),
      );
      expect(subscriptions.calls, isEmpty);

      final catalogs = await Future.wait(<Future<OfficialProfileCatalog>>[
        repository.addManual(name: 'One', rawSource: _firstLink),
        repository.addManual(name: 'Two', rawSource: _secondLink),
      ]);
      expect(catalogs.last.revision, 2);
      final loaded = await repository.load();
      expect(loaded.profiles.map((profile) => profile.name),
          <String>['One', 'Two']);
    });
  });

  test('repository rejects a mismatched store policy', () {
    final storage = MemorySecureValueStore();
    expect(
      () => OfficialProfileRepository(
        policy: const ClientPolicy.whiteLabel(),
        store: SecureOfficialCatalogStore(
          policy: const ClientPolicy.official(),
          storage: storage,
        ),
        subscriptionClient: FakeSubscriptionClient(_document(_firstLink)),
        deviceIdManager: OfficialDeviceIdManager(storage),
      ),
      throwsArgumentError,
    );
  });

  test('White-label policy makes Official storage and transport unreachable',
      () async {
    final storage = MemorySecureValueStore();
    final subscriptions = FakeSubscriptionClient(_document(_firstLink));
    final repository = OfficialProfileRepository(
      policy: const ClientPolicy.whiteLabel(),
      store: SecureOfficialCatalogStore(
        policy: const ClientPolicy.whiteLabel(),
        storage: storage,
      ),
      subscriptionClient: subscriptions,
      deviceIdManager: OfficialDeviceIdManager(storage),
    );

    await expectLater(repository.load(), throwsA(isA<ClientPolicyViolation>()));
    await expectLater(
      repository.addManual(name: 'Forbidden', rawSource: _firstLink),
      throwsA(isA<ClientPolicyViolation>()),
    );
    await expectLater(
      repository.addSubscription(
        name: 'Forbidden',
        url: 'https://panel.example/sub',
      ),
      throwsA(isA<ClientPolicyViolation>()),
    );
    expect(storage.values, isEmpty);
    expect(subscriptions.calls, isEmpty);
  });
}

OfficialSubscriptionDocument _document(String raw, {String? etag}) {
  final parsed = const OfficialConfigParser().parse(raw);
  return OfficialSubscriptionDocument(
    rawBody: raw,
    configs: parsed,
    notModified: false,
    etag: etag,
    usage: const OfficialSubscriptionUsage(
      uploadBytes: 10,
      downloadBytes: 20,
      totalBytes: 100,
    ),
    updateInterval: const Duration(hours: 12),
  );
}
