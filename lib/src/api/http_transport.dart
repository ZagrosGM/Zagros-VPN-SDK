import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import '../models/error.dart';
import 'transport.dart';

class HttpApiTransport implements ApiTransport {
  HttpApiTransport({
    required Uri baseUri,
    http.Client? client,
    this.policy = const TransportPolicy(),
    bool allowInsecureHttp = false,
  })  : baseUri = _validateBaseUri(baseUri, allowInsecureHttp: allowInsecureHttp),
        _client = client ?? _createDefaultClient(allowInsecureHttp: allowInsecureHttp);

  static http.Client _createDefaultClient({bool allowInsecureHttp = false}) {
    if (allowInsecureHttp) {
      final inner = HttpClient()
        ..badCertificateCallback = (cert, host, port) => true;
      return IOClient(inner);
    }
    return http.Client();
  }

  final Uri baseUri;
  final http.Client _client;
  final TransportPolicy policy;

  static Uri _validateBaseUri(Uri uri, {bool allowInsecureHttp = false}) {
    final loopback =
        uri.host == 'localhost' || uri.host == '127.0.0.1' || uri.host == '::1';
    if (!uri.hasScheme ||
        uri.host.isEmpty ||
        (uri.scheme != 'https' && !loopback && !allowInsecureHttp)) {
      throw ArgumentError('Application API base URI must use HTTPS');
    }
    if (uri.hasQuery || uri.hasFragment || uri.userInfo.isNotEmpty) {
      throw ArgumentError(
        'Application API base URI must not contain credentials/query/fragment',
      );
    }
    return uri;
  }

  @override
  Future<ApiResponse> send(ApiRequest request) => mapTransportErrors(() async {
        final relative = request.rawQuery.isEmpty
            ? request.path
            : '${request.path}?${request.rawQuery}';
        final uri = baseUri.resolve(relative);
        final httpRequest = http.Request(request.method, uri)
          ..followRedirects = false
          ..headers.addAll(request.headers)
          ..bodyBytes = request.body;
        final streamed =
            await _client.send(httpRequest).timeout(policy.timeout);
        final builder = BytesBuilder(copy: false);
        var length = 0;
        await for (final chunk in streamed.stream.timeout(policy.timeout)) {
          length += chunk.length;
          if (length > policy.maximumResponseBytes) {
            throw const ZagrosTransportException(
              'Application API response is too large',
            );
          }
          builder.add(chunk);
        }
        return ApiResponse(
          statusCode: streamed.statusCode,
          headers: <String, String>{
            for (final entry in streamed.headers.entries)
              entry.key.toLowerCase(): entry.value,
          },
          body: builder.takeBytes(),
        );
      });

  void close() => _client.close();
}
