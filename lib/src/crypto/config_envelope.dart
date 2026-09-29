import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../models/config.dart';
import '../models/error.dart';
import 'encoding.dart';

const String configEnvelopeAlgorithm =
    'X25519X2-HKDF-SHA256-AES-256-GCM+Ed25519';
const String _signaturePrefix = 'ZAGROS-APPLICATION-CONFIG-ENVELOPE-V1\n';
const String _configInfo = 'zagros/application/config-envelope/v1';

Object? _sortedJson(Object? value) {
  if (value is Map<String, Object?>) {
    final keys = value.keys.toList()..sort();
    return <String, Object?>{
      for (final key in keys) key: _sortedJson(value[key]),
    };
  }
  if (value is List<Object?>) return value.map(_sortedJson).toList();
  return value;
}

Uint8List _canonicalJson(Map<String, Object?> value) =>
    Uint8List.fromList(utf8.encode(jsonEncode(_sortedJson(value))));

Map<String, Object?> _without(
  Map<String, Object?> source,
  Set<String> excluded,
) =>
    <String, Object?>{
      for (final entry in source.entries)
        if (!excluded.contains(entry.key)) entry.key: entry.value,
    };

abstract interface class ConfigEnvelopeOpener {
  Future<OpenedConfig> open({
    required ConfigEnvelope envelope,
    required SimpleKeyPair deviceKeyPair,
    required SimplePublicKey applicationConfigPublicKey,
    required SimplePublicKey applicationSigningPublicKey,
    required DateTime now,
    required String expectedApplicationId,
    required String expectedDeviceId,
  });
}

class CryptographicConfigEnvelopeOpener implements ConfigEnvelopeOpener {
  const CryptographicConfigEnvelopeOpener();

  @override
  Future<OpenedConfig> open({
    required ConfigEnvelope envelope,
    required SimpleKeyPair deviceKeyPair,
    required SimplePublicKey applicationConfigPublicKey,
    required SimplePublicKey applicationSigningPublicKey,
    required DateTime now,
    required String expectedApplicationId,
    required String expectedDeviceId,
  }) =>
      openConfigEnvelope(
        envelope: envelope,
        deviceKeyPair: deviceKeyPair,
        applicationConfigPublicKey: applicationConfigPublicKey,
        applicationSigningPublicKey: applicationSigningPublicKey,
        now: now,
        expectedApplicationId: expectedApplicationId,
        expectedDeviceId: expectedDeviceId,
      );
}

Future<OpenedConfig> openConfigEnvelope({
  required ConfigEnvelope envelope,
  required SimpleKeyPair deviceKeyPair,
  required SimplePublicKey applicationConfigPublicKey,
  required SimplePublicKey applicationSigningPublicKey,
  required DateTime now,
  required String expectedApplicationId,
  required String expectedDeviceId,
}) async {
  if (envelope.version != 1 || envelope.algorithm != configEnvelopeAlgorithm) {
    throw const ZagrosException(
      ZagrosErrorKind.envelopeInvalid,
      'Unsupported config envelope',
    );
  }
  if (envelope.applicationId != expectedApplicationId ||
      envelope.deviceId != expectedDeviceId) {
    throw const ZagrosException(
      ZagrosErrorKind.envelopeInvalid,
      'Config envelope binding mismatch',
    );
  }
  final json = envelope.toJson();
  try {
    final signature = Signature(
      decodeBase64Url(envelope.signature, expectedLength: 64),
      publicKey: applicationSigningPublicKey,
    );
    final signingInput = <int>[
      ...utf8.encode(_signaturePrefix),
      ..._canonicalJson(_without(json, <String>{'signature'})),
    ];
    if (!await Ed25519().verify(signingInput, signature: signature)) {
      throw const ZagrosException(
        ZagrosErrorKind.envelopeInvalid,
        'Config envelope signature invalid',
      );
    }
  } on ZagrosException {
    rethrow;
  } catch (error) {
    throw ZagrosException(
      ZagrosErrorKind.envelopeInvalid,
      'Config envelope signature invalid',
      cause: error,
    );
  }

  if (envelope.issuedAt > envelope.notBefore + 600 ||
      envelope.notBefore >= envelope.expiresAt ||
      envelope.ciphertext.length > 350000) {
    throw const ZagrosException(
      ZagrosErrorKind.envelopeInvalid,
      'Config envelope claims are invalid',
    );
  }
  final nowSeconds = now.toUtc().millisecondsSinceEpoch ~/ 1000;
  if (nowSeconds < envelope.notBefore - 600 ||
      nowSeconds >= envelope.expiresAt) {
    throw const ZagrosException(
      ZagrosErrorKind.envelopeExpired,
      'Config envelope is outside its validity window',
    );
  }

  try {
    final salt = decodeBase64Url(envelope.salt, expectedLength: 32);
    final ephemeralPublicKey = SimplePublicKey(
      decodeBase64Url(envelope.ephemeralPublicKey, expectedLength: 32),
      type: KeyPairType.x25519,
    );
    final nonce = decodeBase64Url(envelope.nonce, expectedLength: 12);
    final ciphertextAndTag = decodeBase64Url(envelope.ciphertext);
    if (ciphertextAndTag.length < 17) {
      throw const FormatException('short ciphertext');
    }
    final staticShared = await X25519().sharedSecretKey(
      keyPair: deviceKeyPair,
      remotePublicKey: applicationConfigPublicKey,
    );
    final ephemeralShared = await X25519().sharedSecretKey(
      keyPair: deviceKeyPair,
      remotePublicKey: ephemeralPublicKey,
    );
    final staticBytes = Uint8List.fromList(await staticShared.extractBytes());
    final ephemeralBytes = Uint8List.fromList(
      await ephemeralShared.extractBytes(),
    );
    final combined = Uint8List(staticBytes.length + ephemeralBytes.length)
      ..setAll(0, staticBytes)
      ..setAll(staticBytes.length, ephemeralBytes);
    Uint8List? plaintext;
    try {
      final aad = _canonicalJson(_without(json, <String>{'ct', 'signature'}));
      final aadHash = await Sha256().hash(aad);
      final key = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: SecretKey(combined),
        nonce: salt,
        info: <int>[...utf8.encode('$_configInfo\u0000'), ...aadHash.bytes],
      );
      final tagOffset = ciphertextAndTag.length - 16;
      final box = SecretBox(
        ciphertextAndTag.sublist(0, tagOffset),
        nonce: nonce,
        mac: Mac(ciphertextAndTag.sublist(tagOffset)),
      );
      plaintext = Uint8List.fromList(
        await AesGcm.with256bits().decrypt(box, secretKey: key, aad: aad),
      );
      return OpenedConfig(envelope: envelope, plaintext: plaintext);
    } finally {
      wipeBytes(staticBytes);
      wipeBytes(ephemeralBytes);
      wipeBytes(combined);
      if (plaintext != null) wipeBytes(plaintext);
    }
  } on ZagrosException {
    rethrow;
  } catch (error) {
    throw ZagrosException(
      ZagrosErrorKind.envelopeInvalid,
      'Config envelope authentication failed',
      cause: error,
    );
  }
}
