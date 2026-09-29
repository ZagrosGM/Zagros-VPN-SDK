import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

class CapturingTransport implements ApiTransport {
  CapturingTransport(this.response);
  final ApiResponse response;
  ApiRequest? request;

  @override
  Future<ApiResponse> send(ApiRequest request) async {
    this.request = request;
    return response;
  }
}

class MemoryValueStore implements SecureValueStore {
  final Map<String, List<int>> values = <String, List<int>>{};
  int writes = 0;

  @override
  Future<void> delete(String key) async => values.remove(key);

  @override
  Future<List<int>?> read(String key) async {
    await Future<void>.delayed(Duration.zero);
    final value = values[key];
    return value == null ? null : List<int>.from(value);
  }

  @override
  Future<void> write(String key, List<int> value) async {
    writes += 1;
    values[key] = List<int>.from(value);
  }
}

void main() {
  test('signed executor emits the authoritative request signature', () async {
    final device = await DeviceIdentity.fromPrivateBytes(
      decodeBase64Url('ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A'),
    );
    final application = ApplicationIdentity(
      applicationId: '11111111-2222-3333-4444-555555555555',
      name: 'Vector',
      status: 'active',
      configKeyId: 'cfg-test-1',
      configPublicKey: decodeBase64Url(
        'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw',
      ),
      signingKeyId: 'sig-test-1',
      signingPublicKey: List<int>.filled(32, 1),
    );
    final transport = CapturingTransport(
      ApiResponse(
        statusCode: 200,
        headers: const <String, String>{},
        body: Uint8List.fromList(utf8.encode('{}')),
      ),
    );
    final executor = SignedRequestExecutor(
      transport: transport,
      application: application,
      deviceKeyPair: device.keyPair,
      clock: () =>
          DateTime.fromMillisecondsSinceEpoch(1770000000 * 1000, isUtc: true),
      nonce: () => 'abcdefghijklmnop',
    );
    await executor.jsonRequest(
      method: 'POST',
      path: '/api/application/v1/auth/login',
      rawQuery: 'b=2&a=1',
      deviceId: 'dev-test-1',
      jsonBody: <String, Object?>{'username': 'alice'},
    );
    final request = transport.request!;
    expect(utf8.decode(request.body), '{"username":"alice"}');
    expect(
      request.headers['x-zagros-signature'],
      'P1G1OlKOtH8PukHWSw45aCvf8r2WadxoDMOH-cR-yRs',
    );
  });

  test('signed executor maps structured API errors', () async {
    final device = await DeviceIdentity.generate();
    final application = ApplicationIdentity(
      applicationId: 'application-1',
      name: 'Test',
      status: 'active',
      configKeyId: 'key-1',
      configPublicKey: List<int>.filled(32, 1),
      signingKeyId: 'sig-1',
      signingPublicKey: List<int>.filled(32, 2),
    );
    final transport = CapturingTransport(
      ApiResponse(
        statusCode: 429,
        headers: const <String, String>{'retry-after': '300'},
        body: Uint8List.fromList(
          utf8.encode(
            jsonEncode(<String, Object?>{
              'detail': <String, Object?>{
                'error': 'rate_limited',
                'message': 'try later',
              },
            }),
          ),
        ),
      ),
    );
    final executor = SignedRequestExecutor(
      transport: transport,
      application: application,
      deviceKeyPair: device.keyPair,
    );
    await expectLater(
      executor.jsonRequest(method: 'GET', path: '/api/application/v1/configs'),
      throwsA(
        isA<ZagrosApiException>()
            .having((error) => error.kind, 'kind', ZagrosErrorKind.rateLimited)
            .having(
              (error) => error.retryAfter,
              'retryAfter',
              const Duration(seconds: 300),
            ),
      ),
    );
  });

  test('HTTP transport rejects plaintext non-loopback origins', () {
    expect(
      () => HttpApiTransport(baseUri: Uri.parse('http://vpn.example')),
      throwsArgumentError,
    );
  });

  test('device identity creation is coalesced and persisted once', () async {
    final store = MemoryValueStore();
    final manager = DeviceIdentityManager(store);
    final identities = await Future.wait(<Future<DeviceIdentity>>[
      manager.loadOrCreate(),
      manager.loadOrCreate(),
      manager.loadOrCreate(),
    ]);
    expect(store.writes, 1);
    expect(
      identities.map((identity) => identity.publicKeyBase64Url).toSet(),
      hasLength(1),
    );
    final restored = await manager.loadOrCreate();
    expect(restored.publicKeyBase64Url, identities.first.publicKeyBase64Url);
  });
}
