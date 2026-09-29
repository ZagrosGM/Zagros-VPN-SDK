import 'dart:math';

import '../crypto/encoding.dart';
import '../storage/secure_storage.dart';

class OfficialDeviceIdManager {
  OfficialDeviceIdManager(this.storage, {Random? random})
      : _random = random ?? Random.secure();

  static const String storageKey = 'zagros.official.device-id.v1';

  final SecureValueStore storage;
  final Random _random;
  Future<String>? _loading;

  Future<String> loadOrCreate() {
    final inFlight = _loading;
    if (inFlight != null) return inFlight;
    final loading = _loadOrCreate();
    _loading = loading;
    return loading.whenComplete(() {
      if (identical(_loading, loading)) _loading = null;
    });
  }

  Future<String> _loadOrCreate() async {
    final stored = await storage.read(storageKey);
    if (stored != null) {
      final value = String.fromCharCodes(stored);
      if (_valid(value)) return value;
      throw const FormatException('stored Official device ID is invalid');
    }
    final bytes = List<int>.generate(32, (_) => _random.nextInt(256));
    final value = 'zg_${base64UrlNoPadding(bytes)}';
    await storage.write(storageKey, value.codeUnits);
    return value;
  }

  Future<void> delete() => storage.delete(storageKey);

  bool _valid(String value) =>
      value.length >= 8 &&
      value.length <= 256 &&
      value.codeUnits.every((code) => code >= 33 && code <= 126);
}
