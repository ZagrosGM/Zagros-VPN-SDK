import 'json.dart';

class ApplicationCredentials {
  const ApplicationCredentials({
    required this.username,
    required this.password,
  });

  final String username;
  final String password;

  @override
  String toString() => 'ApplicationCredentials(username: ***, password: ***)';
}

class AuthTokens {
  const AuthTokens({
    required this.accessToken,
    required this.accessExpiresAt,
    required this.refreshToken,
    required this.refreshExpiresAt,
    required this.tokenType,
  });

  factory AuthTokens.fromJson(Map<String, Object?> json) => AuthTokens(
        accessToken: requiredString(json, 'access_token'),
        accessExpiresAt: requiredDateTime(json, 'access_expires_at'),
        refreshToken: requiredString(json, 'refresh_token'),
        refreshExpiresAt: requiredDateTime(json, 'refresh_expires_at'),
        tokenType: requiredString(json, 'token_type'),
      );

  final String accessToken;
  final DateTime accessExpiresAt;
  final String refreshToken;
  final DateTime refreshExpiresAt;
  final String tokenType;

  @override
  String toString() => 'AuthTokens(**redacted**)';
}

class EnrollmentResult {
  const EnrollmentResult({
    required this.deviceId,
    required this.deviceKeyFingerprint,
    required this.tokens,
  });

  factory EnrollmentResult.fromJson(Map<String, Object?> json) =>
      EnrollmentResult(
        deviceId: requiredString(json, 'device_id'),
        deviceKeyFingerprint: requiredString(json, 'device_key_fingerprint'),
        tokens: AuthTokens.fromJson(requiredObject(json, 'tokens')),
      );

  final String deviceId;
  final String deviceKeyFingerprint;
  final AuthTokens tokens;
}
