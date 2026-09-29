import 'dart:convert';

import '../api/application_api.dart';
import '../models/auth.dart';
import '../models/error.dart';
import '../storage/secure_storage.dart';

class ApplicationSession {
  ApplicationSession({
    required this.api,
    required this.deviceId,
    required this.storage,
    DateTime Function()? clock,
    this.refreshSkew = const Duration(seconds: 30),
  }) : clock = clock ?? DateTime.now;

  final ApplicationApi api;
  final String deviceId;
  final SecureTokenStore storage;
  final DateTime Function() clock;
  final Duration refreshSkew;
  AuthTokens? _tokens;
  Future<AuthTokens>? _refreshing;

  AuthTokens? get current => _tokens;

  Future<void> restore() async {
    final serialized = await storage.read();
    if (serialized == null) return;
    try {
      final value = jsonDecode(serialized);
      if (value is! Map<String, Object?>) throw const FormatException();
      _tokens = AuthTokens.fromJson(value);
    } catch (_) {
      await clear();
    }
  }

  Future<void> setTokens(AuthTokens tokens) async {
    _tokens = tokens;
    await storage.write(
      jsonEncode(<String, Object?>{
        'access_token': tokens.accessToken,
        'access_expires_at': tokens.accessExpiresAt.toUtc().toIso8601String(),
        'refresh_token': tokens.refreshToken,
        'refresh_expires_at': tokens.refreshExpiresAt.toUtc().toIso8601String(),
        'token_type': tokens.tokenType,
      }),
    );
  }

  Future<String> accessToken({bool forceRefresh = false}) async {
    final tokens = _tokens;
    if (tokens == null) {
      throw const ZagrosException(
        ZagrosErrorKind.authentication,
        'Application session is not authenticated',
      );
    }
    final now = clock().toUtc();
    if (now.isAfter(tokens.refreshExpiresAt) ||
        now.isAtSameMomentAs(tokens.refreshExpiresAt)) {
      await clear();
      throw const ZagrosException(
        ZagrosErrorKind.authentication,
        'Application session expired',
      );
    }
    if (!forceRefresh &&
        now.add(refreshSkew).isBefore(tokens.accessExpiresAt)) {
      return tokens.accessToken;
    }
    final inFlight = _refreshing;
    if (inFlight != null) return (await inFlight).accessToken;
    final future = api.refresh(
      deviceId: deviceId,
      refreshToken: tokens.refreshToken,
    );
    _refreshing = future;
    try {
      final refreshed = await future;
      await setTokens(refreshed);
      return refreshed.accessToken;
    } on ZagrosApiException catch (error) {
      if (error.statusCode == 401 || error.statusCode == 403) await clear();
      rethrow;
    } finally {
      _refreshing = null;
    }
  }

  Future<void> clear() async {
    _tokens = null;
    await storage.delete();
  }

  Future<void> logout() async {
    final refreshToken = _tokens?.refreshToken;
    try {
      if (refreshToken != null) {
        await api.logout(deviceId: deviceId, refreshToken: refreshToken);
      }
    } finally {
      await clear();
    }
  }
}
