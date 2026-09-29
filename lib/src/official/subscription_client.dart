import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../models/error.dart';
import '../parsers/parser_limits.dart';
import 'file_refs.dart';
import 'models.dart';
import 'parser.dart';

abstract interface class OfficialSubscriptionClient {
  Future<OfficialSubscriptionDocument> fetch(
    Uri uri, {
    required String deviceId,
    String? etag,
    String? lastModified,
  });

  void close();
}

class HttpOfficialSubscriptionClient implements OfficialSubscriptionClient {
  HttpOfficialSubscriptionClient({
    http.Client? client,
    this.parser = const OfficialConfigParser(),
    this.timeout = const Duration(seconds: 20),
    this.maximumRedirects = 3,
    this.maximumResponseBytes = maximumConfigBytes,
  }) : _client = client ?? http.Client() {
    if (timeout <= Duration.zero || timeout > const Duration(minutes: 2)) {
      throw ArgumentError.value(timeout, 'timeout');
    }
    if (maximumRedirects < 0 || maximumRedirects > 5) {
      throw ArgumentError.value(maximumRedirects, 'maximumRedirects');
    }
    if (maximumResponseBytes < 1024 ||
        maximumResponseBytes > maximumConfigBytes) {
      throw ArgumentError.value(maximumResponseBytes, 'maximumResponseBytes');
    }
  }

  final http.Client _client;
  final OfficialConfigParser parser;
  final Duration timeout;
  final int maximumRedirects;
  final int maximumResponseBytes;

  @override
  Future<OfficialSubscriptionDocument> fetch(
    Uri uri, {
    required String deviceId,
    String? etag,
    String? lastModified,
  }) async {
    final initial = _validateUri(uri);
    _validateDeviceId(deviceId);
    _validateConditionalHeader(etag);
    _validateConditionalHeader(lastModified);
    try {
      var current = initial;
      for (var redirect = 0; redirect <= maximumRedirects; redirect += 1) {
        final request = http.Request('GET', current)
          ..followRedirects = false
          ..headers.addAll(<String, String>{
            'accept': 'text/plain, application/json, text/yaml;q=0.9',
            'user-agent': 'Zagros-VPN/0.1',
            'x-device-id': deviceId,
            if (etag != null && etag.isNotEmpty) 'if-none-match': etag,
            if (lastModified != null && lastModified.isNotEmpty)
              'if-modified-since': lastModified,
          });
        final response = await _client.send(request).timeout(timeout);
        if (_redirectStatuses.contains(response.statusCode)) {
          await _discard(response.stream);
          if (redirect >= maximumRedirects) {
            throw const ZagrosException(
              ZagrosErrorKind.transport,
              'Subscription redirected too many times',
            );
          }
          final location = response.headers['location'];
          if (location == null || location.length > 2048) {
            throw const ZagrosException(
              ZagrosErrorKind.malformedResponse,
              'Subscription redirect is invalid',
            );
          }
          final next = _validateUri(current.resolve(location));
          if (!_sameOrigin(initial, next)) {
            throw const ZagrosException(
              ZagrosErrorKind.secureTransportRequired,
              'Cross-origin subscription redirect is forbidden',
            );
          }
          current = next;
          continue;
        }
        if (response.statusCode == 304) {
          await _discard(response.stream);
          return OfficialSubscriptionDocument(
            rawBody: '',
            configs: const <ParsedOfficialConfig>[],
            fileRefs: const <OfficialFileRef>[],
            notModified: true,
            etag: _safeHeader(response.headers['etag']) ?? etag,
            lastModified:
                _safeHeader(response.headers['last-modified']) ?? lastModified,
            usage: _parseUsage(response.headers['subscription-userinfo']),
            updateInterval: _parseUpdateInterval(
              response.headers['profile-update-interval'],
            ),
          );
        }
        if (response.statusCode != 200) {
          await _discard(response.stream);
          throw _statusError(response.statusCode);
        }
        final contentLength = response.contentLength;
        if (contentLength != null && contentLength > maximumResponseBytes) {
          await _discard(response.stream);
          throw const ZagrosException(
            ZagrosErrorKind.malformedResponse,
            'Subscription response is too large',
          );
        }
        final builder = BytesBuilder(copy: false);
        var received = 0;
        await for (final chunk in response.stream.timeout(timeout)) {
          received += chunk.length;
          if (received > maximumResponseBytes) {
            throw const ZagrosException(
              ZagrosErrorKind.malformedResponse,
              'Subscription response is too large',
            );
          }
          builder.add(chunk);
        }
        final rawBody = utf8.decode(builder.takeBytes(), allowMalformed: false);
        final configs = parser.parse(rawBody);
        return OfficialSubscriptionDocument(
          rawBody: rawBody,
          configs: configs,
          fileRefs: parser.fileRefs(rawBody),
          notModified: false,
          etag: _safeHeader(response.headers['etag']),
          lastModified: _safeHeader(response.headers['last-modified']),
          usage: _parseUsage(response.headers['subscription-userinfo']),
          updateInterval: _parseUpdateInterval(
            response.headers['profile-update-interval'],
          ),
        );
      }
      throw StateError('unreachable redirect state');
    } on ZagrosException {
      rethrow;
    } on TimeoutException catch (error) {
      throw ZagrosTransportException(
        'Subscription request timed out',
        cause: error,
      );
    } on FormatException catch (error) {
      throw ZagrosException(
        ZagrosErrorKind.malformedResponse,
        'Subscription response is malformed',
        cause: error,
      );
    } catch (error) {
      throw ZagrosTransportException(
        'Subscription transport failed',
        cause: error,
      );
    }
  }

  Future<void> _discard(Stream<List<int>> stream) async {
    var received = 0;
    await for (final chunk in stream.timeout(timeout)) {
      received += chunk.length;
      if (received > maximumResponseBytes) break;
    }
  }

  static const _redirectStatuses = <int>{301, 302, 303, 307, 308};

  static Uri _validateUri(Uri uri) {
    final loopback =
        uri.host == 'localhost' || uri.host == '127.0.0.1' || uri.host == '::1';
    if (!uri.hasScheme ||
        uri.host.isEmpty ||
        uri.port < 1 ||
        uri.port > 65535 ||
        (uri.scheme != 'https' && !(loopback && uri.scheme == 'http')) ||
        uri.userInfo.isNotEmpty ||
        uri.hasFragment) {
      throw const ZagrosException(
        ZagrosErrorKind.secureTransportRequired,
        'Subscription URL must use HTTPS',
      );
    }
    return uri;
  }

  static bool _sameOrigin(Uri first, Uri second) =>
      first.scheme == second.scheme &&
      first.host == second.host &&
      first.port == second.port;

  static void _validateDeviceId(String value) {
    if (value.length < 8 ||
        value.length > 256 ||
        value.codeUnits.any((code) => code < 33 || code > 126)) {
      throw const ZagrosException(
        ZagrosErrorKind.validation,
        'Official device ID is invalid',
      );
    }
  }

  static void _validateConditionalHeader(String? value) {
    if (value == null) return;
    if (value.length > 512 ||
        value.codeUnits.any((code) => code < 32 || code > 126)) {
      throw const ZagrosException(
        ZagrosErrorKind.validation,
        'Subscription cache validator is invalid',
      );
    }
  }

  static String? _safeHeader(String? value) {
    if (value == null ||
        value.isEmpty ||
        value.length > 512 ||
        value.codeUnits.any((code) => code < 32 || code > 126)) {
      return null;
    }
    return value;
  }

  static OfficialSubscriptionUsage? _parseUsage(String? value) {
    if (value == null || value.isEmpty || value.length > 2048) return null;
    final fields = <String, int>{};
    for (final segment in value.split(';')) {
      final separator = segment.indexOf('=');
      if (separator < 1) continue;
      final key = segment.substring(0, separator).trim().toLowerCase();
      final parsed = int.tryParse(segment.substring(separator + 1).trim());
      if (parsed != null && parsed >= 0 && parsed <= 9223372036854775807) {
        fields[key] = parsed;
      }
    }
    if (!fields.containsKey('upload') &&
        !fields.containsKey('download') &&
        !fields.containsKey('total') &&
        !fields.containsKey('expire')) {
      return null;
    }
    final expires = fields['expire'];
    DateTime? expiresAt;
    if (expires != null && expires > 0 && expires <= 8640000000000) {
      try {
        expiresAt = DateTime.fromMillisecondsSinceEpoch(
          expires * 1000,
          isUtc: true,
        );
      } on RangeError {
        expiresAt = null;
      }
    }
    return OfficialSubscriptionUsage(
      uploadBytes: fields['upload'] ?? 0,
      downloadBytes: fields['download'] ?? 0,
      totalBytes: fields['total'] ?? 0,
      expiresAt: expiresAt,
    );
  }

  static Duration? _parseUpdateInterval(String? value) {
    if (value == null || value.length > 32) return null;
    final hours = int.tryParse(value.trim());
    if (hours == null || hours < 1 || hours > 168) return null;
    return Duration(hours: hours);
  }

  static ZagrosException _statusError(int statusCode) {
    final kind = switch (statusCode) {
      401 => ZagrosErrorKind.authentication,
      403 => ZagrosErrorKind.authorization,
      404 => ZagrosErrorKind.validation,
      429 => ZagrosErrorKind.rateLimited,
      _ when statusCode >= 500 => ZagrosErrorKind.transport,
      _ => ZagrosErrorKind.unknown,
    };
    return ZagrosException(kind, 'Subscription request was rejected');
  }

  @override
  void close() => _client.close();
}
