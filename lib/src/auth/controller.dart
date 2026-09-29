import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../api/application_api.dart';
import '../models/auth.dart';
import '../models/error.dart';
import '../storage/secure_storage.dart';
import 'session.dart';

class ApplicationAuthController {
  ApplicationAuthController({
    required this.api,
    required this.tokenStorage,
    required this.identityStorage,
    this.applicationPublicId,
    this.appSigningSeed,
    this.appSigningKeyId,
    DateTime Function()? clock,
  }) : clock = clock ?? DateTime.now;

  final ApplicationApi api;
  final SecureTokenStore tokenStorage;
  final SecureValueStore identityStorage;
  final DateTime Function() clock;

  /// Build-embedded Ed25519 seed (32 bytes) of the application signing key.
  /// Present in official builds; lets the app enroll a device with just the
  /// user's credentials — no activation code — while the panel verifies the
  /// signature against the active signing key (rotation = kill switch).
  final Uint8List? appSigningSeed;
  final String? appSigningKeyId;
  final String? applicationPublicId;

  static const String _attestPrefix = 'ZAGROS-APP-ATTEST-V1';

  /// Canonical attestation bytes; must match the panel byte-for-byte.
  Uint8List _attestationMessage(String username) {
    if (applicationPublicId == null || appSigningKeyId == null) {
      throw const FormatException('app attestation identity is incomplete');
    }
    final fields = <String>[
      _attestPrefix,
      applicationPublicId!,
      appSigningKeyId!,
      username,
      api.deviceIdentity.publicKeyBase64Url,
    ];
    for (final field in fields) {
      if (field.contains('\n') || field.contains('\r')) {
        throw const FormatException('invalid attestation field');
      }
    }
    return Uint8List.fromList(utf8.encode('${fields.join('\n')}\n'));
  }

  Future<String> _signAttestation(String username) async {
    final seed = appSigningSeed;
    if (seed == null || seed.length != 32) {
      throw const FormatException('app signing seed is missing or invalid');
    }
    final pair = await Ed25519().newKeyPairFromSeed(seed);
    final signature = await Ed25519().sign(
      _attestationMessage(username),
      keyPair: pair,
    );
    return base64Url.encode(signature.bytes).replaceAll('=', '');
  }
  static const String deviceIdStorageKey = 'zagros.application.device.id.v1';
  ApplicationSession? _session;

  ApplicationSession? get session => _session;

  Future<ApplicationSession?> restore() async {
    final bytes = await identityStorage.read(deviceIdStorageKey);
    if (bytes == null) return null;
    String id;
    try {
      id = utf8.decode(bytes, allowMalformed: false);
      if (id.isEmpty || id.length > 128) {
        throw const FormatException('invalid device id');
      }
    } on FormatException {
      await identityStorage.delete(deviceIdStorageKey);
      await tokenStorage.delete();
      return null;
    }
    final restored = ApplicationSession(
      api: api,
      deviceId: id,
      storage: tokenStorage,
      clock: clock,
    );
    await restored.restore();
    _session = restored;
    return restored;
  }

  Future<ApplicationSession> enroll({
    required ApplicationCredentials credentials,
    String activationTicket = '',
    String? deviceName,
    String? platform,
    String? appVersion,
  }) async {
    String? appSignature;
    if (activationTicket.isEmpty && appSigningSeed != null) {
      appSignature = await _signAttestation(credentials.username);
    }
    final result = await api.enroll(
      credentials: credentials,
      activationTicket: activationTicket,
      appSignature: appSignature,
      appSigningKeyId: activationTicket.isEmpty ? appSigningKeyId : null,
      deviceName: deviceName,
      platform: platform,
      appVersion: appVersion,
    );
    await identityStorage.write(
      deviceIdStorageKey,
      utf8.encode(result.deviceId),
    );
    final created = ApplicationSession(
      api: api,
      deviceId: result.deviceId,
      storage: tokenStorage,
      clock: clock,
    );
    await created.setTokens(result.tokens);
    _session = created;
    return created;
  }

  Future<ApplicationSession> login(ApplicationCredentials credentials) async {
    final active = _session ?? await restore();
    // A password alone can never (re-)enroll a device: the server requires a
    // fresh activation ticket for enrollment. Silently falling back with an
    // empty ticket produced an unactionable 422 — surface enrollmentRequired
    // instead so the UI can ask for the activation code.
    if (active == null) {
      throw const ZagrosException(
        ZagrosErrorKind.enrollmentRequired,
        'device enrollment required; obtain an activation code',
      );
    }
    try {
      await active.setTokens(
        await api.login(deviceId: active.deviceId, credentials: credentials),
      );
      return active;
    } on ZagrosException catch (error) {
      // The stored device identity is no longer recognized by the server:
      // re-enrollment needs a fresh activation code from the panel.
      rethrow;
    }
  }

  Future<void> logout() async {
    await _session?.logout();
  }

  Future<void> forgetEnrollment() async {
    await _session?.clear();
    await identityStorage.delete(deviceIdStorageKey);
    _session = null;
  }
}
