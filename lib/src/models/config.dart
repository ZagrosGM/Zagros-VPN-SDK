import 'dart:typed_data';

import 'json.dart';

class ConfigSelector {
  const ConfigSelector({
    required this.coreId,
    required this.protocol,
    required this.engine,
    required this.displayName,
    required this.status,
    this.configId,
    this.expiresAt,
  });

  factory ConfigSelector.fromJson(Map<String, Object?> json) => ConfigSelector(
        configId: optionalString(json, 'config_id'),
        coreId: requiredString(json, 'core_id'),
        protocol: requiredString(json, 'protocol'),
        engine: json['engine'] is String ? json['engine']! as String : '',
        displayName: requiredString(json, 'display_name'),
        status: requiredString(json, 'status'),
        expiresAt: optionalDateTime(json, 'expires_at'),
      );

  final String? configId;
  final String coreId;
  final String protocol;
  final String engine;
  final String displayName;
  final String status;
  final DateTime? expiresAt;

  bool get connectable => status == 'active' && configId != null;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ConfigSelector &&
          runtimeType == other.runtimeType &&
          (configId != null && other.configId != null
              ? configId == other.configId
              : coreId == other.coreId &&
                  protocol == other.protocol &&
                  displayName == other.displayName);

  @override
  int get hashCode => (configId ?? '$coreId-$protocol-$displayName').hashCode;
}

class ConfigEnvelope {
  const ConfigEnvelope({
    required this.version,
    required this.algorithm,
    required this.applicationId,
    required this.applicationKeyId,
    required this.signingKeyId,
    required this.deviceId,
    required this.configId,
    required this.coreId,
    required this.protocol,
    required this.engine,
    required this.issuedAt,
    required this.notBefore,
    required this.expiresAt,
    required this.salt,
    required this.ephemeralPublicKey,
    required this.nonce,
    required this.ciphertext,
    required this.signature,
    this.connectionId,
  });

  factory ConfigEnvelope.fromJson(Map<String, Object?> json) => ConfigEnvelope(
        version: requiredInt(json, 'v'),
        algorithm: requiredString(json, 'alg'),
        applicationId: requiredString(json, 'application_id'),
        applicationKeyId: requiredString(json, 'application_key_id'),
        signingKeyId: requiredString(json, 'signing_key_id'),
        deviceId: requiredString(json, 'device_id'),
        configId: requiredString(json, 'config_id'),
        connectionId: optionalString(json, 'connection_id'),
        coreId: requiredString(json, 'core_id'),
        protocol: requiredString(json, 'protocol'),
        engine: requiredString(json, 'engine'),
        issuedAt: requiredInt(json, 'issued_at'),
        notBefore: requiredInt(json, 'not_before'),
        expiresAt: requiredInt(json, 'expires_at'),
        salt: requiredString(json, 'salt'),
        ephemeralPublicKey: requiredString(json, 'eph'),
        nonce: requiredString(json, 'nonce'),
        ciphertext: requiredString(json, 'ct'),
        signature: requiredString(json, 'signature'),
      );

  final int version;
  final String algorithm;
  final String applicationId;
  final String applicationKeyId;
  final String signingKeyId;
  final String deviceId;
  final String configId;
  final String? connectionId;
  final String coreId;
  final String protocol;
  final String engine;
  final int issuedAt;
  final int notBefore;
  final int expiresAt;
  final String salt;
  final String ephemeralPublicKey;
  final String nonce;
  final String ciphertext;
  final String signature;

  Map<String, Object?> toJson() => <String, Object?>{
        'v': version,
        'alg': algorithm,
        'application_id': applicationId,
        'application_key_id': applicationKeyId,
        'signing_key_id': signingKeyId,
        'device_id': deviceId,
        'config_id': configId,
        'connection_id': connectionId,
        'core_id': coreId,
        'protocol': protocol,
        'engine': engine,
        'issued_at': issuedAt,
        'not_before': notBefore,
        'expires_at': expiresAt,
        'salt': salt,
        'eph': ephemeralPublicKey,
        'nonce': nonce,
        'ct': ciphertext,
        'signature': signature,
      };
}

class OpenedConfig {
  OpenedConfig({required this.envelope, required List<int> plaintext})
      : plaintext = Uint8List.fromList(plaintext);

  final ConfigEnvelope envelope;
  final Uint8List plaintext;

  void dispose() => plaintext.fillRange(0, plaintext.length, 0);

  @override
  String toString() => 'OpenedConfig(${envelope.protocol}, **redacted**)';
}

enum ConfigSourceFormat {
  uri,
  vmessJson,
  singBoxJson,
  clashYaml,
  wireGuardIni,
  openVpn,
  fields,
}

class VpnEndpoint {
  const VpnEndpoint({required this.host, required this.port, this.transport});

  final String host;
  final int port;
  final String? transport;
}

class NormalizedConfig {
  NormalizedConfig({
    required this.protocol,
    required this.engine,
    required this.displayName,
    required this.sourceFormat,
    required List<VpnEndpoint> endpoints,
    required Map<String, Object?> credentials,
    required Map<String, Object?> options,
    required Map<String, Object?> extensions,
    required List<String> warnings,
  })  : endpoints = List<VpnEndpoint>.unmodifiable(endpoints),
        credentials = frozenObject(credentials),
        options = frozenObject(options),
        extensions = frozenObject(extensions),
        warnings = List<String>.unmodifiable(warnings);

  final String protocol;
  final String engine;
  final String displayName;
  final ConfigSourceFormat sourceFormat;
  final List<VpnEndpoint> endpoints;
  final Map<String, Object?> credentials;
  final Map<String, Object?> options;
  final Map<String, Object?> extensions;
  final List<String> warnings;

  @override
  String toString() =>
      'NormalizedConfig(protocol: $protocol, engine: $engine, credentials: **redacted**)';
}
