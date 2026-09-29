import 'json.dart';

class ApplicationIdentity {
  ApplicationIdentity({
    required this.applicationId,
    required this.name,
    required this.status,
    required this.configKeyId,
    required List<int> configPublicKey,
    required this.signingKeyId,
    required List<int> signingPublicKey,
  })  : configPublicKey = List<int>.unmodifiable(configPublicKey),
        signingPublicKey = List<int>.unmodifiable(signingPublicKey) {
    if (configPublicKey.length != 32 || signingPublicKey.length != 32) {
      throw ArgumentError('Application public keys must be 32 bytes');
    }
  }

  final String applicationId;
  final String name;
  final String status;
  final String configKeyId;
  final List<int> configPublicKey;
  final String signingKeyId;
  final List<int> signingPublicKey;
}

class ApplicationView {
  const ApplicationView({
    required this.applicationId,
    required this.name,
    required this.defaultLanguage,
    required this.branding,
  });

  factory ApplicationView.fromJson(Map<String, Object?> json) =>
      ApplicationView(
        applicationId: requiredString(json, 'application_id'),
        name: requiredString(json, 'name'),
        defaultLanguage: requiredString(json, 'default_lang'),
        branding: frozenObject(requiredObject(json, 'branding')),
      );

  final String applicationId;
  final String name;
  final String defaultLanguage;
  final Map<String, Object?> branding;
}

class UserProfile {
  const UserProfile({
    required this.username,
    required this.status,
    required this.online,
    required this.usedBytes,
    required this.application,
    this.dataLimitBytes,
    this.remainingBytes,
    this.expiresAt,
  });

  factory UserProfile.fromJson(Map<String, Object?> json) => UserProfile(
        username: optionalString(json, 'username') ?? '',
        status: requiredString(json, 'status'),
        online: requiredBool(json, 'online'),
        usedBytes: requiredInt(json, 'used_bytes'),
        dataLimitBytes: optionalInt(json, 'data_limit_bytes'),
        remainingBytes: optionalInt(json, 'remaining_bytes'),
        expiresAt: optionalDateTime(json, 'expire_at'),
        application:
            ApplicationView.fromJson(requiredObject(json, 'application')),
      );

  final String username;
  final String status;
  final bool online;
  final int usedBytes;
  final int? dataLimitBytes;
  final int? remainingBytes;
  final DateTime? expiresAt;
  final ApplicationView application;
}

class ApplicationDevice {
  const ApplicationDevice({
    required this.deviceId,
    required this.keyFingerprint,
    required this.status,
    required this.isCurrent,
    required this.firstSeen,
    required this.lastSeen,
    this.name,
    this.platform,
    this.appVersion,
    this.lastAuthenticatedAt,
    this.revokedAt,
  });

  factory ApplicationDevice.fromJson(Map<String, Object?> json) =>
      ApplicationDevice(
        deviceId: requiredString(json, 'device_id'),
        keyFingerprint: requiredString(json, 'key_fingerprint'),
        status: requiredString(json, 'status'),
        isCurrent: requiredBool(json, 'is_current'),
        firstSeen: requiredDateTime(json, 'first_seen'),
        lastSeen: requiredDateTime(json, 'last_seen'),
        name: optionalString(json, 'name'),
        platform: optionalString(json, 'platform'),
        appVersion: optionalString(json, 'app_version'),
        lastAuthenticatedAt: optionalDateTime(json, 'last_authenticated_at'),
        revokedAt: optionalDateTime(json, 'revoked_at'),
      );

  final String deviceId;
  final String keyFingerprint;
  final String status;
  final bool isCurrent;
  final DateTime firstSeen;
  final DateTime lastSeen;
  final String? name;
  final String? platform;
  final String? appVersion;
  final DateTime? lastAuthenticatedAt;
  final DateTime? revokedAt;
}
