import '../auth/session.dart';
import '../models/application.dart';
import '../models/config.dart';
import '../models/connection.dart';
import '../models/error.dart';
import '../models/usage.dart';
import 'application_api.dart';
import 'pagination.dart';

class AuthenticatedApplicationClient {
  const AuthenticatedApplicationClient({
    required this.api,
    required this.session,
  });

  final ApplicationApi api;
  final ApplicationSession session;

  Future<UserProfile> profile() =>
      _safe((token) => api.profile(session.deviceId, token));

  Future<List<ApplicationDevice>> devices() =>
      _safe((token) => api.devices(session.deviceId, token));

  Future<List<ConfigSelector>> configs() =>
      _safe((token) => api.listConfigs(session.deviceId, token));

  Future<List<ConnectionInfo>> connections({String? connectionId}) => _safe(
        (token) => api.connectionStatus(
          deviceId: session.deviceId,
          accessToken: token,
          connectionId: connectionId,
        ),
      );

  Future<UsageSummary> usageSummary() =>
      _safe((token) => api.usageSummary(session.deviceId, token));

  Future<UsageHistoryPage> usageHistory({
    DateTime? from,
    DateTime? to,
    String granularity = 'day',
    int limit = 30,
    String? cursor,
  }) =>
      _safe(
        (token) => api.usageHistory(
          deviceId: session.deviceId,
          accessToken: token,
          from: from,
          to: to,
          granularity: granularity,
          limit: limit,
          cursor: cursor,
        ),
      );

  Stream<UsageBucket> allUsageHistory({
    DateTime? from,
    DateTime? to,
    String granularity = 'day',
    int pageSize = 100,
    int maximumPages = 1000,
  }) =>
      paginate<UsageBucket>(
        maximumPages: maximumPages,
        load: (cursor) async {
          final page = await usageHistory(
            from: from,
            to: to,
            granularity: granularity,
            limit: pageSize,
            cursor: cursor,
          );
          return CursorPage<UsageBucket>(
            items: page.items,
            nextCursor: page.nextCursor,
          );
        },
      );

  Future<T> _safe<T>(Future<T> Function(String accessToken) request) async {
    var token = await session.accessToken();
    try {
      return await request(token);
    } on ZagrosApiException catch (error) {
      if (error.kind != ZagrosErrorKind.authentication) rethrow;
      token = await session.accessToken(forceRefresh: true);
      return request(token);
    }
  }
}
