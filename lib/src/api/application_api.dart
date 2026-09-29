import '../crypto/device_identity.dart';
import '../models/application.dart';
import '../models/auth.dart';
import '../models/config.dart';
import '../models/connection.dart';
import '../models/json.dart';
import '../models/usage.dart';
import 'signed_executor.dart';

class ApplicationApi {
  const ApplicationApi({required this.executor, required this.deviceIdentity});

  final SignedRequestExecutor executor;
  final DeviceIdentity deviceIdentity;
  static const String prefix = '/api/application/v1';

  Future<EnrollmentResult> enroll({
    required ApplicationCredentials credentials,
    String activationTicket = '',
    String? appSignature,
    String? appSigningKeyId,
    String? deviceName,
    String? platform,
    String? appVersion,
  }) async {
    final json = await executor.jsonRequest(
      method: 'POST',
      path: '$prefix/devices/enroll',
      jsonBody: <String, Object?>{
        'username': credentials.username,
        'password': credentials.password,
        // A non-empty ticket is the legacy QR/reseller flow. The default app
        // path sends an app-build attestation instead of any user-facing code.
        if (activationTicket.isNotEmpty) 'activation_ticket': activationTicket,
        if (appSignature != null) 'app_signature': appSignature,
        if (appSigningKeyId != null) 'app_kid': appSigningKeyId,
        'device_public_key': deviceIdentity.publicKeyBase64Url,
        'device_name': deviceName,
        'platform': platform,
        'app_version': appVersion,
      },
    );
    return EnrollmentResult.fromJson(json);
  }

  Future<AuthTokens> login({
    required String deviceId,
    required ApplicationCredentials credentials,
  }) async =>
      AuthTokens.fromJson(
        await executor.jsonRequest(
          method: 'POST',
          path: '$prefix/auth/login',
          deviceId: deviceId,
          jsonBody: <String, Object?>{
            'username': credentials.username,
            'password': credentials.password,
          },
        ),
      );

  Future<AuthTokens> refresh({
    required String deviceId,
    required String refreshToken,
  }) async =>
      AuthTokens.fromJson(
        await executor.jsonRequest(
          method: 'POST',
          path: '$prefix/auth/refresh',
          deviceId: deviceId,
          jsonBody: <String, Object?>{'refresh_token': refreshToken},
        ),
      );

  Future<void> logout({
    required String deviceId,
    required String refreshToken,
  }) async {
    await executor.jsonRequest(
      method: 'POST',
      path: '$prefix/auth/logout',
      deviceId: deviceId,
      jsonBody: <String, Object?>{'refresh_token': refreshToken},
    );
  }

  Future<UserProfile> profile(String deviceId, String accessToken) async =>
      UserProfile.fromJson(
        await _protectedGet('$prefix/user/profile', deviceId, accessToken),
      );

  Future<List<ApplicationDevice>> devices(
    String deviceId,
    String accessToken,
  ) async {
    final json = await _protectedGet('$prefix/devices', deviceId, accessToken);
    return requiredList(json, 'devices')
        .map((Object? value) => ApplicationDevice.fromJson(objectMap(value)))
        .toList(growable: false);
  }

  Future<void> revokeDevice({
    required String deviceId,
    required String targetDeviceId,
    required String accessToken,
    required String password,
  }) async {
    await executor.jsonRequest(
      method: 'POST',
      path: '$prefix/devices/${Uri.encodeComponent(targetDeviceId)}/revoke',
      deviceId: deviceId,
      accessToken: accessToken,
      jsonBody: <String, Object?>{'password': password},
    );
  }

  Future<List<ConfigSelector>> listConfigs(
    String deviceId,
    String accessToken,
  ) async {
    final json = await _protectedGet('$prefix/configs', deviceId, accessToken);
    return requiredList(json, 'configs')
        .map((Object? value) => ConfigSelector.fromJson(objectMap(value)))
        .toList(growable: false);
  }

  Future<ConnectionInfo> startConnection({
    required String deviceId,
    required String accessToken,
    required String configId,
  }) async =>
      ConnectionInfo.fromJson(
        await executor.jsonRequest(
          method: 'POST',
          path: '$prefix/connections/start',
          deviceId: deviceId,
          accessToken: accessToken,
          jsonBody: <String, Object?>{'config_id': configId},
        ),
      );

  Future<ConfigEnvelope> consumeConfig({
    required String deviceId,
    required String accessToken,
    required String configId,
  }) async =>
      ConfigEnvelope.fromJson(
        await _protectedGet(
          '$prefix/configs/${Uri.encodeComponent(configId)}',
          deviceId,
          accessToken,
        ),
      );

  Future<ConnectionInfo> stopConnection({
    required String deviceId,
    required String accessToken,
    required String connectionId,
  }) async =>
      ConnectionInfo.fromJson(
        await executor.jsonRequest(
          method: 'POST',
          path: '$prefix/connections/${Uri.encodeComponent(connectionId)}/stop',
          deviceId: deviceId,
          accessToken: accessToken,
          jsonBody: const <String, Object?>{},
        ),
      );

  Future<List<ConnectionInfo>> connectionStatus({
    required String deviceId,
    required String accessToken,
    String? connectionId,
    bool renew = false,
  }) async {
    final parameters = <MapEntry<String, String>>[
      if (connectionId != null)
        MapEntry<String, String>('connection_id', connectionId),
      if (renew) const MapEntry<String, String>('renew', 'true'),
    ];
    final rawQuery = parameters
        .map(
          (entry) => '${Uri.encodeQueryComponent(entry.key)}='
              '${Uri.encodeQueryComponent(entry.value)}',
        )
        .join('&');
    final json = await executor.jsonRequest(
      method: 'GET',
      path: '$prefix/connections/status',
      rawQuery: rawQuery,
      deviceId: deviceId,
      accessToken: accessToken,
    );
    return requiredList(json, 'connections')
        .map((Object? value) => ConnectionInfo.fromJson(objectMap(value)))
        .toList(growable: false);
  }

  Future<UsageSummary> usageSummary(
    String deviceId,
    String accessToken,
  ) async =>
      UsageSummary.fromJson(
        await _protectedGet('$prefix/usage/summary', deviceId, accessToken),
      );

  Future<UsageHistoryPage> usageHistory({
    required String deviceId,
    required String accessToken,
    DateTime? from,
    DateTime? to,
    String granularity = 'day',
    int limit = 30,
    String? cursor,
  }) async {
    if (granularity != 'hour' && granularity != 'day') {
      throw ArgumentError.value(granularity, 'granularity');
    }
    if (limit < 1 || limit > 100) {
      throw RangeError.range(limit, 1, 100, 'limit');
    }
    final parameters = <MapEntry<String, String>>[
      if (from != null)
        MapEntry<String, String>('from', from.toUtc().toIso8601String()),
      if (to != null)
        MapEntry<String, String>('to', to.toUtc().toIso8601String()),
      MapEntry<String, String>('granularity', granularity),
      MapEntry<String, String>('limit', limit.toString()),
      if (cursor != null) MapEntry<String, String>('cursor', cursor),
    ];
    final rawQuery = parameters
        .map(
          (entry) => '${Uri.encodeQueryComponent(entry.key)}='
              '${Uri.encodeQueryComponent(entry.value)}',
        )
        .join('&');
    final json = await executor.jsonRequest(
      method: 'GET',
      path: '$prefix/usage/history',
      rawQuery: rawQuery,
      deviceId: deviceId,
      accessToken: accessToken,
    );
    return UsageHistoryPage.fromJson(json);
  }

  Future<Map<String, Object?>> _protectedGet(
    String path,
    String deviceId,
    String accessToken,
  ) =>
      executor.jsonRequest(
        method: 'GET',
        path: path,
        deviceId: deviceId,
        accessToken: accessToken,
      );
}
