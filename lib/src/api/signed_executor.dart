import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../crypto/canonical_request.dart';
import '../crypto/encoding.dart';
import '../models/application.dart';
import '../models/error.dart';
import '../models/json.dart';
import 'transport.dart';

class SignedRequestExecutor {
  SignedRequestExecutor({
    required this.transport,
    required this.application,
    required this.deviceKeyPair,
    DateTime Function()? clock,
    String Function()? nonce,
  })  : clock = clock ?? DateTime.now,
        nonce = nonce ?? _secureNonce;

  final ApiTransport transport;
  final ApplicationIdentity application;
  final SimpleKeyPair deviceKeyPair;
  final DateTime Function() clock;
  final String Function() nonce;

  static String _secureNonce() {
    final random = Random.secure();
    return base64UrlNoPadding(
      List<int>.generate(24, (_) => random.nextInt(256)),
    );
  }

  Future<Map<String, Object?>> jsonRequest({
    required String method,
    required String path,
    String rawQuery = '',
    Map<String, Object?>? jsonBody,
    String? deviceId,
    String? accessToken,
  }) async {
    final body = jsonBody == null
        ? Uint8List(0)
        : Uint8List.fromList(utf8.encode(jsonEncode(jsonBody)));
    final timestamp = clock().toUtc().millisecondsSinceEpoch ~/ 1000;
    final requestNonce = nonce();
    final input = CanonicalRequestInput(
      method: method,
      path: path,
      rawQuery: rawQuery,
      timestamp: timestamp,
      nonce: requestNonce,
      applicationId: application.applicationId,
      applicationKeyId: application.configKeyId,
      deviceId: deviceId,
      body: body,
    );
    final signature = await signRequest(
      input: input,
      deviceKeyPair: deviceKeyPair,
      applicationPublicKey: SimplePublicKey(
        application.configPublicKey,
        type: KeyPairType.x25519,
      ),
    );
    final headers = <String, String>{
      'content-type': 'application/json',
      'accept': 'application/json',
      'x-zagros-application-id': application.applicationId,
      'x-zagros-application-key-id': application.configKeyId,
      'x-zagros-device-id': deviceId ?? '-',
      'x-zagros-timestamp': timestamp.toString(),
      'x-zagros-nonce': requestNonce,
      'x-zagros-signature': signature,
      if (accessToken != null) 'authorization': 'Bearer $accessToken',
    };
    final response = await transport.send(
      ApiRequest(
        method: method,
        path: path,
        rawQuery: rawQuery,
        headers: headers,
        body: body,
      ),
    );
    Object? decoded;
    try {
      decoded = response.body.isEmpty
          ? <String, Object?>{}
          : jsonDecode(utf8.decode(response.body, allowMalformed: false));
    } catch (error) {
      throw ZagrosException(
        ZagrosErrorKind.malformedResponse,
        'Application API returned invalid JSON',
        cause: error,
      );
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final root = decoded is Map<Object?, Object?>
          ? objectMap(decoded)
          : <String, Object?>{};
      final detailValue = root['detail'];
      final detail =
          detailValue is Map<Object?, Object?> ? objectMap(detailValue) : root;
      final code = detail['error']?.toString() ?? 'http_${response.statusCode}';
      final message =
          detail['message']?.toString() ?? 'Application API request failed';
      final retrySeconds = int.tryParse(response.headers['retry-after'] ?? '');
      throw ZagrosApiException(
        statusCode: response.statusCode,
        code: code,
        message: message,
        retryAfter:
            retrySeconds == null ? null : Duration(seconds: retrySeconds),
      );
    }
    if (decoded is! Map<Object?, Object?>) {
      throw const ZagrosException(
        ZagrosErrorKind.malformedResponse,
        'Application API response must be an object',
      );
    }
    return objectMap(decoded);
  }
}
