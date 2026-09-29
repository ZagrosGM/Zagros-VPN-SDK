import 'dart:convert';
import 'dart:typed_data';

final RegExp _base64UrlPattern = RegExp(r'^[A-Za-z0-9_-]+$');

String base64UrlNoPadding(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List decodeBase64Url(String value, {int? expectedLength}) {
  if (value.isEmpty || !_base64UrlPattern.hasMatch(value)) {
    throw const FormatException('invalid base64url value');
  }
  try {
    final decoded = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(value)),
    );
    if (expectedLength != null && decoded.length != expectedLength) {
      throw const FormatException('invalid encoded length');
    }
    return decoded;
  } on FormatException {
    rethrow;
  } catch (_) {
    throw const FormatException('invalid base64url value');
  }
}

String hexLower(List<int> bytes) =>
    bytes.map((int byte) => byte.toRadixString(16).padLeft(2, '0')).join();

void wipeBytes(List<int> bytes) {
  if (bytes is Uint8List) bytes.fillRange(0, bytes.length, 0);
}
