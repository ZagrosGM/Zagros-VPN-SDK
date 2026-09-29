import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../models/error.dart';
import 'file_refs.dart';

/// Maximum bytes accepted for one downloaded file payload.
///
/// The panel's profiles are small (a WireGuard config is hundreds of bytes);
/// anything larger is a corrupt or hostile response, never a profile.
const int maximumFileBytes = 64 * 1024;

/// Maximum file markers resolved into entries during one refresh.
///
/// Downloads are sequential and each costs a round trip; beyond this the
/// remaining markers are reported as errors instead of stalling the refresh.
const int maximumFilesPerRefresh = 8;

abstract interface class OfficialFileDownloadClient {
  /// Download one marker payload.
  ///
  /// [subscriptionUri] is the subscription the marker came from: the fetch
  /// target is `ref.resolve(subscriptionUri)`, so a marker can never pull
  /// the client off that origin. Throws [ZagrosException] on transport or
  /// protocol failures and [FormatException] on escaping references.
  Future<String> fetchFile({
    required Uri subscriptionUri,
    required OfficialFileRef ref,
    required String deviceId,
  });

  void close();
}

class HttpOfficialFileDownloadClient implements OfficialFileDownloadClient {
  HttpOfficialFileDownloadClient({
    http.Client? client,
    this.timeout = const Duration(seconds: 20),
    this.maximumResponseBytes = maximumFileBytes,
  }) : _client = client ?? http.Client() {
    if (timeout <= Duration.zero || timeout > const Duration(minutes: 2)) {
      throw ArgumentError.value(timeout, 'timeout');
    }
    if (maximumResponseBytes < 1024 ||
        maximumResponseBytes > maximumFileBytes) {
      throw ArgumentError.value(maximumResponseBytes, 'maximumResponseBytes');
    }
  }

  final http.Client _client;
  final Duration timeout;
  final int maximumResponseBytes;

  @override
  Future<String> fetchFile({
    required Uri subscriptionUri,
    required OfficialFileRef ref,
    required String deviceId,
  }) async {
    // Same-origin by construction: resolve() throws when the marker path
    // escapes the subscription's scheme/host/port.
    final target = _validateTarget(ref.resolve(subscriptionUri));
    _validateDeviceId(deviceId);
    try {
      final request = http.Request('GET', target)
        ..followRedirects = false
        ..headers.addAll(<String, String>{
          'accept': 'text/plain, application/*;q=0.9',
          'user-agent': 'Zagros-VPN/0.1',
          'x-device-id': deviceId,
        });
      final response = await _client.send(request).timeout(timeout);
      if (response.statusCode != 200) {
        await _discard(response.stream);
        throw _statusError(response.statusCode);
      }
      final contentLength = response.contentLength;
      if (contentLength != null && contentLength > maximumResponseBytes) {
        await _discard(response.stream);
        throw const ZagrosException(
          ZagrosErrorKind.malformedResponse,
          'File payload is too large',
        );
      }
      final builder = BytesBuilder(copy: false);
      var received = 0;
      await for (final chunk in response.stream.timeout(timeout)) {
        received += chunk.length;
        if (received > maximumResponseBytes) {
          throw const ZagrosException(
            ZagrosErrorKind.malformedResponse,
            'File payload is too large',
          );
        }
        builder.add(chunk);
      }
      final text = utf8.decode(builder.takeBytes(), allowMalformed: false);
      if (text.trim().isEmpty) {
        throw const ZagrosException(
          ZagrosErrorKind.malformedResponse,
          'File payload is empty',
        );
      }
      return text;
    } on ZagrosException {
      rethrow;
    } on TimeoutException catch (error) {
      throw ZagrosTransportException('File download timed out', cause: error);
    } on FormatException catch (error) {
      throw ZagrosException(
        ZagrosErrorKind.malformedResponse,
        'File payload is malformed',
        cause: error,
      );
    } catch (error) {
      throw ZagrosTransportException('File download failed', cause: error);
    }
  }

  Future<void> _discard(Stream<List<int>> stream) async {
    var received = 0;
    await for (final chunk in stream.timeout(timeout)) {
      received += chunk.length;
      if (received > maximumResponseBytes) break;
    }
  }

  static Uri _validateTarget(Uri uri) {
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
        'File URL must use HTTPS',
      );
    }
    return uri;
  }

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

  static ZagrosException _statusError(int statusCode) {
    final kind = switch (statusCode) {
      401 => ZagrosErrorKind.authentication,
      403 => ZagrosErrorKind.authorization,
      404 => ZagrosErrorKind.validation,
      429 => ZagrosErrorKind.rateLimited,
      _ when statusCode >= 500 => ZagrosErrorKind.transport,
      _ => ZagrosErrorKind.unknown,
    };
    return ZagrosException(kind, 'File download was rejected');
  }

  @override
  void close() => _client.close();
}
