import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../storage/secure_storage.dart';
import 'encoding.dart';

class DeviceIdentity {
  DeviceIdentity._({required this.keyPair, required this.publicKeyBytes});

  final SimpleKeyPair keyPair;
  final Uint8List publicKeyBytes;

  String get publicKeyBase64Url => base64UrlNoPadding(publicKeyBytes);

  static Future<DeviceIdentity> generate() async {
    final pair = await X25519().newKeyPair();
    final publicKey = await pair.extractPublicKey();
    return DeviceIdentity._(
      keyPair: pair,
      publicKeyBytes: Uint8List.fromList(publicKey.bytes),
    );
  }

  static Future<DeviceIdentity> fromPrivateBytes(List<int> privateBytes) async {
    if (privateBytes.length != 32) {
      throw const FormatException('X25519 private key must be 32 bytes');
    }
    final algorithm = X25519();
    final pair = await algorithm.newKeyPairFromSeed(privateBytes);
    final publicKey = await pair.extractPublicKey();
    return DeviceIdentity._(
      keyPair: pair,
      publicKeyBytes: Uint8List.fromList(publicKey.bytes),
    );
  }

  Future<Uint8List> extractPrivateBytes() async =>
      Uint8List.fromList(await keyPair.extractPrivateKeyBytes());
}

class DeviceIdentityManager {
  DeviceIdentityManager(this.storage);

  final SecureValueStore storage;
  static const String storageKey = 'zagros.application.device.x25519.v1';
  Future<DeviceIdentity>? _loading;

  Future<DeviceIdentity> loadOrCreate() {
    final inFlight = _loading;
    if (inFlight != null) return inFlight;
    final loading = _loadOrCreate();
    _loading = loading;
    return loading.whenComplete(() {
      if (identical(_loading, loading)) _loading = null;
    });
  }

  Future<DeviceIdentity> _loadOrCreate() async {
    final stored = await storage.read(storageKey);
    if (stored != null) return DeviceIdentity.fromPrivateBytes(stored);
    final created = await DeviceIdentity.generate();
    final privateBytes = await created.extractPrivateBytes();
    try {
      // SecureValueStore.write must consume/copy the bytes before completing.
      await storage.write(storageKey, privateBytes);
    } finally {
      wipeBytes(privateBytes);
    }
    return created;
  }

  Future<void> delete() => storage.delete(storageKey);
}
