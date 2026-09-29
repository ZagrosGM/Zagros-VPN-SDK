import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

Map<String, Object?> readObject(String path) {
  final Object? value = jsonDecode(File(path).readAsStringSync());
  return Map<String, Object?>.from(value! as Map<Object?, Object?>);
}

Map<String, Object?> nested(Map<String, Object?> value, String key) =>
    Map<String, Object?>.from(value[key]! as Map<Object?, Object?>);

void main() {
  group('Python/Dart request vector', () {
    late Map<String, Object?> fixture;
    late Map<String, Object?> request;
    late Map<String, Object?> keys;

    setUpAll(() {
      fixture = readObject('test/fixtures/application_request_v1.json');
      request = nested(fixture, 'request');
      keys = nested(fixture, 'x25519');
    });

    test('canonical bytes match Python', () async {
      final canonical = await canonicalRequest(
        CanonicalRequestInput(
          method: request['method']! as String,
          path: request['path']! as String,
          rawQuery: request['raw_query']! as String,
          timestamp: request['timestamp']! as int,
          nonce: request['nonce']! as String,
          applicationId: request['application_id']! as String,
          applicationKeyId: request['application_key_id']! as String,
          deviceId: request['device_id']! as String,
          body: utf8.encode(request['body_utf8']! as String),
        ),
      );
      expect(utf8.decode(canonical), request['canonical_utf8']);
    });

    test('X25519 HKDF and HMAC match Python', () async {
      final device = await DeviceIdentity.fromPrivateBytes(
        decodeBase64Url(keys['device_private_b64url']! as String),
      );
      final key = await deriveRequestMacKey(
        deviceKeyPair: device.keyPair,
        applicationPublicKey: SimplePublicKey(
          decodeBase64Url(keys['server_public_b64url']! as String),
          type: KeyPairType.x25519,
        ),
        applicationId: request['application_id']! as String,
        applicationKeyId: request['application_key_id']! as String,
        deviceId: request['device_id']! as String,
      );
      expect(
        base64UrlNoPadding(await key.extractBytes()),
        keys['derived_mac_key_b64url'],
      );
      expect(
        await signCanonicalRequest(
          utf8.encode(request['canonical_utf8']! as String),
          key,
        ),
        keys['signature_b64url'],
      );
    });
  });

  group('Python/Dart config envelope vector', () {
    late Map<String, Object?> fixture;
    late Map<String, Object?> keys;
    late Map<String, Object?> envelopeJson;

    setUpAll(() {
      fixture = readObject('test/fixtures/application_config_envelope_v1.json');
      keys = nested(fixture, 'keys');
      envelopeJson = nested(fixture, 'envelope');
    });

    test('verifies and decrypts Python envelope', () async {
      final device = await DeviceIdentity.fromPrivateBytes(
        decodeBase64Url(keys['device_private_b64url']! as String),
      );
      final opened = await openConfigEnvelope(
        envelope: ConfigEnvelope.fromJson(envelopeJson),
        deviceKeyPair: device.keyPair,
        applicationConfigPublicKey: SimplePublicKey(
          decodeBase64Url(keys['application_config_public_b64url']! as String),
          type: KeyPairType.x25519,
        ),
        applicationSigningPublicKey: SimplePublicKey(
          decodeBase64Url(keys['application_signing_public_b64url']! as String),
          type: KeyPairType.ed25519,
        ),
        now: DateTime.fromMillisecondsSinceEpoch(
          1770000001 * 1000,
          isUtc: true,
        ),
        expectedApplicationId: envelopeJson['application_id']! as String,
        expectedDeviceId: envelopeJson['device_id']! as String,
      );
      expect(utf8.decode(opened.plaintext), fixture['payload_utf8']);
      opened.dispose();
      expect(opened.plaintext, everyElement(0));
    });

    test('rejects signature tampering before decryption', () async {
      final tampered = Map<String, Object?>.from(envelopeJson)
        ..['protocol'] = 'trojan';
      final device = await DeviceIdentity.fromPrivateBytes(
        decodeBase64Url(keys['device_private_b64url']! as String),
      );
      await expectLater(
        openConfigEnvelope(
          envelope: ConfigEnvelope.fromJson(tampered),
          deviceKeyPair: device.keyPair,
          applicationConfigPublicKey: SimplePublicKey(
            decodeBase64Url(
              keys['application_config_public_b64url']! as String,
            ),
            type: KeyPairType.x25519,
          ),
          applicationSigningPublicKey: SimplePublicKey(
            decodeBase64Url(
              keys['application_signing_public_b64url']! as String,
            ),
            type: KeyPairType.ed25519,
          ),
          now: DateTime.fromMillisecondsSinceEpoch(
            1770000001 * 1000,
            isUtc: true,
          ),
          expectedApplicationId: envelopeJson['application_id']! as String,
          expectedDeviceId: envelopeJson['device_id']! as String,
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.envelopeInvalid,
          ),
        ),
      );
    });

    test('rejects expired signed envelope', () async {
      final device = await DeviceIdentity.fromPrivateBytes(
        decodeBase64Url(keys['device_private_b64url']! as String),
      );
      await expectLater(
        openConfigEnvelope(
          envelope: ConfigEnvelope.fromJson(envelopeJson),
          deviceKeyPair: device.keyPair,
          applicationConfigPublicKey: SimplePublicKey(
            decodeBase64Url(
              keys['application_config_public_b64url']! as String,
            ),
            type: KeyPairType.x25519,
          ),
          applicationSigningPublicKey: SimplePublicKey(
            decodeBase64Url(
              keys['application_signing_public_b64url']! as String,
            ),
            type: KeyPairType.ed25519,
          ),
          now: DateTime.fromMillisecondsSinceEpoch(
            1770000030 * 1000,
            isUtc: true,
          ),
          expectedApplicationId: envelopeJson['application_id']! as String,
          expectedDeviceId: envelopeJson['device_id']! as String,
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.envelopeExpired,
          ),
        ),
      );
    });
  });
}
