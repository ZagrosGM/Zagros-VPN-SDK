import 'dart:convert';
import 'dart:math';

import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

const _link =
    'vless://00000000-0000-0000-0000-000000000001@vpn.example:443?security=tls&type=tcp#Primary';

class MemorySecureValueStore implements SecureValueStore {
  final Map<String, List<int>> values = <String, List<int>>{};
  String? failNextWriteFor;

  @override
  Future<void> delete(String key) async {
    values.remove(key);
  }

  @override
  Future<List<int>?> read(String key) async {
    final value = values[key];
    return value == null ? null : List<int>.of(value);
  }

  @override
  Future<void> write(String key, List<int> value) async {
    if (failNextWriteFor == key) {
      failNextWriteFor = null;
      throw StateError('injected protected-store failure');
    }
    values[key] = List<int>.of(value);
  }
}

void main() {
  group('Official device identity', () {
    test(
      'is stable, separate, opaque, and coalesces concurrent creation',
      () async {
        final storage = MemorySecureValueStore();
        final manager = OfficialDeviceIdManager(storage, random: Random(7));
        final values = await Future.wait(<Future<String>>[
          manager.loadOrCreate(),
          manager.loadOrCreate(),
          manager.loadOrCreate(),
        ]);
        expect(values.toSet(), hasLength(1));
        final value = values.first;
        expect(value, startsWith('zg_'));
        expect(value.length, greaterThan(40));
        expect(
          utf8.decode(storage.values[OfficialDeviceIdManager.storageKey]!),
          value,
        );
        expect(await manager.loadOrCreate(), value);
      },
    );

    test('fails closed for malformed protected identity', () async {
      final storage = MemorySecureValueStore()
        ..values[OfficialDeviceIdManager.storageKey] = utf8.encode('bad id');
      await expectLater(
        OfficialDeviceIdManager(storage).loadOrCreate(),
        throwsFormatException,
      );
    });
  });

  group('protected Official catalog', () {
    test('White-label policy denies direct Official store access', () async {
      final storage = MemorySecureValueStore();
      final store = SecureOfficialCatalogStore(
        policy: const ClientPolicy.whiteLabel(),
        storage: storage,
      );
      await expectLater(store.load(), throwsA(isA<ClientPolicyViolation>()));
      await expectLater(
        store.save(OfficialProfileCatalog.empty()),
        throwsA(isA<ClientPolicyViolation>()),
      );
      expect(storage.values, isEmpty);
    });

    test(
      'round-trips authoritative raw source and redacts diagnostics',
      () async {
        final storage = MemorySecureValueStore();
        final store = SecureOfficialCatalogStore(
          policy: const ClientPolicy.official(),
          storage: storage,
        );
        final catalog = _catalog(revision: 1, name: 'First');

        await store.save(catalog);
        final loaded = await store.load();

        expect(loaded.revision, 1);
        expect(loaded.profiles.single.name, 'First');
        expect(
          loaded.profiles.single.configs.single.normalized.protocol,
          'vless',
        );
        expect(loaded.profiles.single.rawSource, _link);
        expect(loaded.profiles.single.toString(), isNot(contains(_link)));
        expect(
          loaded.profiles.single.configs.single.toString(),
          isNot(contains(_link)),
        );
        expect(
          storage.values.keys,
          contains('zagros.official.catalog.manifest.v1'),
        );
      },
    );

    test('successful replacement cleans the obsolete protected slot', () async {
      final storage = MemorySecureValueStore();
      final store = SecureOfficialCatalogStore(
        policy: const ClientPolicy.official(),
        storage: storage,
      );
      await store.save(_catalog(revision: 1, name: 'First'));
      final firstManifest = jsonDecode(
        utf8.decode(storage.values['zagros.official.catalog.manifest.v1']!),
      ) as Map<String, Object?>;
      final firstSlot = firstManifest['slot']! as String;
      final firstChunk = 'zagros.official.catalog.$firstSlot.0.v1';
      expect(storage.values, contains(firstChunk));

      await store.save(_catalog(revision: 2, name: 'Second'));

      expect(storage.values, isNot(contains(firstChunk)));
      expect((await store.load()).profiles.single.name, 'Second');
    });

    test(
      'manifest-last alternating slots preserve last good catalog',
      () async {
        final storage = MemorySecureValueStore();
        final store = SecureOfficialCatalogStore(
          policy: const ClientPolicy.official(),
          storage: storage,
        );
        await store.save(_catalog(revision: 1, name: 'Stable'));
        final firstManifest = utf8.decode(
          storage.values['zagros.official.catalog.manifest.v1']!,
        );

        storage.failNextWriteFor = 'zagros.official.catalog.manifest.v1';
        await expectLater(
          store.save(_catalog(revision: 2, name: 'Interrupted')),
          throwsStateError,
        );

        expect(
          utf8.decode(storage.values['zagros.official.catalog.manifest.v1']!),
          firstManifest,
        );
        final recovered = await store.load();
        expect(recovered.revision, 1);
        expect(recovered.profiles.single.name, 'Stable');
      },
    );

    test('detects protected chunk tampering', () async {
      final storage = MemorySecureValueStore();
      final store = SecureOfficialCatalogStore(
        policy: const ClientPolicy.official(),
        storage: storage,
      );
      await store.save(_catalog(revision: 1, name: 'Stable'));
      final manifest = jsonDecode(
        utf8.decode(storage.values['zagros.official.catalog.manifest.v1']!),
      ) as Map<String, Object?>;
      final slot = manifest['slot']! as String;
      final chunkKey = 'zagros.official.catalog.$slot.0.v1';
      storage.values[chunkKey]![0] ^= 1;

      await expectLater(store.load(), throwsFormatException);
    });

    test(
      'rejects forged config entries and insecure subscription sources',
      () async {
        final storage = MemorySecureValueStore();
        final store = SecureOfficialCatalogStore(
          policy: const ClientPolicy.official(),
          storage: storage,
        );
        final parsed = const OfficialConfigParser().parse(_link).single;
        final now = DateTime.utc(2026, 9, 7);
        final forged = OfficialProfile(
          id: 'profile_secure_1',
          name: 'Forged',
          kind: OfficialProfileKind.subscription,
          subscriptionUri: Uri.parse('http://panel.example/sub'),
          rawSource: _link,
          configs: <OfficialConfigEntry>[
            OfficialConfigEntry(
              id: 'wrong.entry',
              rawText: parsed.rawText,
              normalized: parsed.normalized,
            ),
          ],
          createdAt: now,
          updatedAt: now,
        );
        await expectLater(
          store.save(
            OfficialProfileCatalog(
              revision: 1,
              profiles: <OfficialProfile>[forged],
            ),
          ),
          throwsFormatException,
        );
      },
    );
  });
}

OfficialProfileCatalog _catalog({required int revision, required String name}) {
  final parsed = const OfficialConfigParser().parse(_link).single;
  final now = DateTime.utc(2026, 9, 7);
  const id = 'profile_secure_1';
  return OfficialProfileCatalog(
    revision: revision,
    profiles: <OfficialProfile>[
      OfficialProfile(
        id: id,
        name: name,
        kind: OfficialProfileKind.manual,
        rawSource: _link,
        configs: <OfficialConfigEntry>[
          OfficialConfigEntry(
            id: '$id.0',
            rawText: parsed.rawText,
            normalized: parsed.normalized,
          ),
        ],
        createdAt: now,
        updatedAt: now,
      ),
    ],
  );
}
