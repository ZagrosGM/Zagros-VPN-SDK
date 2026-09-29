DateTime requiredDateTime(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! String) {
    throw FormatException('$key must be an ISO-8601 string');
  }
  return DateTime.parse(value).toUtc();
}

DateTime? optionalDateTime(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value == null) return null;
  if (value is! String) {
    throw FormatException('$key must be an ISO-8601 string');
  }
  return DateTime.parse(value).toUtc();
}

String requiredString(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! String || value.isEmpty) {
    throw FormatException('$key must be a non-empty string');
  }
  return value;
}

String? optionalString(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value == null) return null;
  if (value is! String) throw FormatException('$key must be a string');
  return value;
}

int requiredInt(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! int) throw FormatException('$key must be an integer');
  return value;
}

int? optionalInt(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value == null) return null;
  if (value is! int) throw FormatException('$key must be an integer');
  return value;
}

bool requiredBool(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! bool) throw FormatException('$key must be a boolean');
  return value;
}

Map<String, Object?> requiredObject(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! Map<String, Object?>) {
    throw FormatException('$key must be an object');
  }
  return value;
}

List<Object?> requiredList(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! List<Object?>) throw FormatException('$key must be an array');
  return value;
}

Map<String, Object?> objectMap(Object? value, {String name = 'value'}) {
  if (value is! Map<Object?, Object?>) {
    throw FormatException('$name must be an object');
  }
  return value.map((Object? key, Object? item) {
    if (key is! String) throw FormatException('$name has a non-string key');
    return MapEntry<String, Object?>(key, normalizeJson(item));
  });
}

Map<String, Object?> frozenObject(Map<String, Object?> value) =>
    freezeJson(value) as Map<String, Object?>;

Object? freezeJson(Object? value) {
  if (value is Map<String, Object?>) {
    return Map<String, Object?>.unmodifiable(
      value.map(
        (key, item) => MapEntry<String, Object?>(key, freezeJson(item)),
      ),
    );
  }
  if (value is List<Object?>) {
    return List<Object?>.unmodifiable(value.map(freezeJson));
  }
  return value;
}

Object? normalizeJson(Object? value, {int depth = 0}) {
  if (depth > 32) {
    throw const FormatException('JSON value is nested too deeply');
  }
  if (value == null || value is String || value is num || value is bool) {
    return value;
  }
  if (value is List<Object?>) {
    if (value.length > 1000) {
      throw const FormatException('JSON array has too many items');
    }
    return value.map((item) => normalizeJson(item, depth: depth + 1)).toList();
  }
  if (value is Map<Object?, Object?>) {
    if (value.length > 1000) {
      throw const FormatException('JSON object has too many fields');
    }
    return value.map((Object? key, Object? item) {
      if (key is! String) {
        throw const FormatException('JSON object has a non-string key');
      }
      return MapEntry<String, Object?>(
        key,
        normalizeJson(item, depth: depth + 1),
      );
    });
  }
  throw FormatException('unsupported value ${value.runtimeType}');
}
