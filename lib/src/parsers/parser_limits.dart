import 'dart:convert';

const int maximumConfigBytes = 256 * 1024;
const int maximumCollectionItems = 512;
const int maximumNestingDepth = 24;

void enforceTextLimit(String input) {
  if (input.codeUnits.length > maximumConfigBytes ||
      utf8.encode(input).length > maximumConfigBytes) {
    throw const FormatException('configuration exceeds size limit');
  }
}

void enforceJsonShape(Object? value, {int depth = 0}) {
  if (depth > maximumNestingDepth) {
    throw const FormatException('configuration nesting is too deep');
  }
  if (value is List<Object?>) {
    if (value.length > maximumCollectionItems) {
      throw const FormatException('configuration contains too many items');
    }
    for (final item in value) {
      enforceJsonShape(item, depth: depth + 1);
    }
  } else if (value is Map<Object?, Object?>) {
    if (value.length > maximumCollectionItems) {
      throw const FormatException('configuration contains too many fields');
    }
    for (final item in value.values) {
      enforceJsonShape(item, depth: depth + 1);
    }
  }
}

void rejectExternalFileReferences(Object? value, {int depth = 0}) {
  if (depth > maximumNestingDepth) {
    throw const FormatException('configuration nesting is too deep');
  }
  if (value is List<Object?>) {
    for (final item in value) {
      rejectExternalFileReferences(item, depth: depth + 1);
    }
  } else if (value is Map<Object?, Object?>) {
    for (final entry in value.entries) {
      final key = entry.key.toString().toLowerCase().replaceAll('-', '_');
      if (key.endsWith('_file') ||
          const <String>{
            'certificate_path',
            'client_certificate_path',
            'private_key_path',
            'client_key_path',
            'key_path',
            'ca_path',
            'cert_path',
            'password_file',
          }.contains(key)) {
        throw FormatException('external file reference is forbidden: $key');
      }
      rejectExternalFileReferences(entry.value, depth: depth + 1);
    }
  }
}

int validPort(Object? value) {
  final port = value is int ? value : int.tryParse(value?.toString() ?? '');
  if (port == null || port < 1 || port > 65535) {
    throw const FormatException('invalid port');
  }
  return port;
}

String validHost(Object? value) {
  final host = value?.toString().trim() ?? '';
  if (host.isEmpty ||
      host.length > 253 ||
      host.contains(RegExp(r'[\s/\\\x00]'))) {
    throw const FormatException('invalid host');
  }
  return host;
}
