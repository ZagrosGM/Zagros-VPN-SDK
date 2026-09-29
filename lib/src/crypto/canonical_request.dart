import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../models/error.dart';
import 'encoding.dart';

const String canonicalRequestPrefix = 'ZAGROS-APPLICATION-REQUEST-V1';
final RegExp _noncePattern = RegExp(r'^[A-Za-z0-9_-]{16,128}$');
final RegExp _identifierPattern = RegExp(r'^[A-Za-z0-9._-]{1,128}$');
final RegExp _badPercent = RegExp(r'%(?![0-9A-Fa-f]{2})');
const String _requestInfo = 'zagros/application/request-mac/v1';

class CanonicalRequestInput {
  const CanonicalRequestInput({
    required this.method,
    required this.path,
    required this.rawQuery,
    required this.timestamp,
    required this.nonce,
    required this.applicationId,
    required this.applicationKeyId,
    required this.body,
    this.deviceId,
  });

  final String method;
  final String path;
  final String rawQuery;
  final int timestamp;
  final String nonce;
  final String applicationId;
  final String applicationKeyId;
  final String? deviceId;
  final List<int> body;
}

String _percentEncode(String value, {required bool path}) {
  final safe = path ? '/-._~' : '-._~';
  final output = StringBuffer();
  for (final byte in utf8.encode(value)) {
    final char = String.fromCharCode(byte);
    final alphaNumeric = byte >= 0x41 && byte <= 0x5a ||
        byte >= 0x61 && byte <= 0x7a ||
        byte >= 0x30 && byte <= 0x39;
    if (alphaNumeric || safe.contains(char)) {
      output.write(char);
    } else {
      output.write('%${byte.toRadixString(16).toUpperCase().padLeft(2, '0')}');
    }
  }
  return output.toString();
}

String _strictDecode(String value, {required bool query}) {
  if (_badPercent.hasMatch(value)) {
    throw const FormatException('invalid percent encoding');
  }
  return query ? Uri.decodeQueryComponent(value) : Uri.decodeComponent(value);
}

String normalizeTarget(String inputPath, [String rawQuery = '']) {
  var path = inputPath.isEmpty ? '/' : inputPath;
  if (path.length > 2048 || rawQuery.length > 4096) {
    throw const FormatException('request target is too long');
  }
  path = _percentEncode(_strictDecode(path, query: false), path: true);
  if (!path.startsWith('/')) path = '/$path';

  final pairs = <(String, String)>[];
  if (rawQuery.isNotEmpty) {
    final fields = rawQuery.split('&');
    if (fields.length > 100) {
      throw const FormatException('too many query fields');
    }
    for (final field in fields) {
      final separator = field.indexOf('=');
      final rawKey = separator < 0 ? field : field.substring(0, separator);
      final rawValue = separator < 0 ? '' : field.substring(separator + 1);
      pairs.add((
        _percentEncode(_strictDecode(rawKey, query: true), path: false),
        _percentEncode(_strictDecode(rawValue, query: true), path: false),
      ));
    }
  }
  pairs.sort(((String, String) left, (String, String) right) {
    final byKey = left.$1.compareTo(right.$1);
    return byKey != 0 ? byKey : left.$2.compareTo(right.$2);
  });
  final query =
      pairs.map(((String, String) pair) => '${pair.$1}=${pair.$2}').join('&');
  return query.isEmpty ? path : '$path?$query';
}

Future<Uint8List> canonicalRequest(CanonicalRequestInput input) async {
  if (!_noncePattern.hasMatch(input.nonce) ||
      !_identifierPattern.hasMatch(input.applicationId) ||
      !_identifierPattern.hasMatch(input.applicationKeyId) ||
      input.deviceId != null && !_identifierPattern.hasMatch(input.deviceId!)) {
    throw const FormatException('invalid signed request field');
  }
  final digest = await Sha256().hash(input.body);
  final fields = <String>[
    canonicalRequestPrefix,
    input.method.toUpperCase(),
    normalizeTarget(input.path, input.rawQuery),
    input.timestamp.toString(),
    input.nonce,
    input.applicationId,
    input.applicationKeyId,
    input.deviceId ?? '-',
    hexLower(digest.bytes),
  ];
  if (fields.any(
    (String value) => value.contains('\n') || value.contains('\r'),
  )) {
    throw const FormatException('canonical field contains a newline');
  }
  return Uint8List.fromList(utf8.encode('${fields.join('\n')}\n'));
}

Future<SecretKey> deriveRequestMacKey({
  required SimpleKeyPair deviceKeyPair,
  required SimplePublicKey applicationPublicKey,
  required String applicationId,
  required String applicationKeyId,
  String? deviceId,
}) async {
  final scope = '$applicationId\u0000$applicationKeyId\u0000${deviceId ?? '-'}';
  final salt = await Sha256().hash(
    utf8.encode('zagros/application/request-salt/v1\u0000$scope'),
  );
  final shared = await X25519().sharedSecretKey(
    keyPair: deviceKeyPair,
    remotePublicKey: applicationPublicKey,
  );
  return Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: shared,
    nonce: salt.bytes,
    info: utf8.encode('$_requestInfo\u0000$scope'),
  );
}

Future<String> signCanonicalRequest(
  List<int> canonical,
  SecretKey macKey,
) async {
  final mac = await Hmac.sha256().calculateMac(canonical, secretKey: macKey);
  return base64UrlNoPadding(mac.bytes);
}

Future<String> signRequest({
  required CanonicalRequestInput input,
  required SimpleKeyPair deviceKeyPair,
  required SimplePublicKey applicationPublicKey,
}) async {
  try {
    final canonical = await canonicalRequest(input);
    final key = await deriveRequestMacKey(
      deviceKeyPair: deviceKeyPair,
      applicationPublicKey: applicationPublicKey,
      applicationId: input.applicationId,
      applicationKeyId: input.applicationKeyId,
      deviceId: input.deviceId,
    );
    return await signCanonicalRequest(canonical, key);
  } on ZagrosException {
    rethrow;
  } catch (error) {
    throw ZagrosException(
      ZagrosErrorKind.requestSigning,
      'Unable to sign request',
      cause: error,
    );
  }
}
