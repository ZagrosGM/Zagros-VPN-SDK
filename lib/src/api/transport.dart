import 'dart:async';
import 'dart:typed_data';

import '../models/error.dart';

class ApiRequest {
  const ApiRequest({
    required this.method,
    required this.path,
    required this.rawQuery,
    required this.headers,
    required this.body,
  });

  final String method;
  final String path;
  final String rawQuery;
  final Map<String, String> headers;
  final Uint8List body;
}

class ApiResponse {
  const ApiResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
  });

  final int statusCode;
  final Map<String, String> headers;
  final Uint8List body;
}

abstract interface class ApiTransport {
  Future<ApiResponse> send(ApiRequest request);
}

class TransportPolicy {
  const TransportPolicy({
    this.timeout = const Duration(seconds: 20),
    this.maximumResponseBytes = 1024 * 1024,
  });

  final Duration timeout;
  final int maximumResponseBytes;
}

Future<T> mapTransportErrors<T>(Future<T> Function() action) async {
  try {
    return await action();
  } on ZagrosException {
    rethrow;
  } on TimeoutException catch (error) {
    throw ZagrosTransportException(
      'Application API request timed out',
      cause: error,
    );
  } catch (error) {
    throw ZagrosTransportException(
      'Application API transport failed',
      cause: error,
    );
  }
}
