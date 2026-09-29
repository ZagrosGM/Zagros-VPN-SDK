import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

void main() {
  test('API error mapping is stable and low-information', () {
    final expired = ZagrosApiException(
      statusCode: 410,
      code: 'config_grant_expired',
      message: 'expired',
    );
    expect(expired.kind, ZagrosErrorKind.selectorExpired);
    expect(expired.recoverableByFreshAuthority, isTrue);

    final denied = ZagrosApiException(
      statusCode: 403,
      code: 'device_revoked',
      message: 'denied',
    );
    expect(denied.kind, ZagrosErrorKind.authorization);
    expect(denied.recoverableByFreshAuthority, isFalse);
  });

  test('cursor pagination preserves order and terminates', () async {
    final requested = <String?>[];
    final values = await paginate<int>(
      load: (cursor) async {
        requested.add(cursor);
        return switch (cursor) {
          null => CursorPage<int>(items: <int>[1, 2], nextCursor: 'next'),
          'next' => CursorPage<int>(items: <int>[3]),
          _ => throw StateError('unexpected cursor'),
        };
      },
    ).toList();
    expect(values, <int>[1, 2, 3]);
    expect(requested, <String?>[null, 'next']);
  });

  test('cursor pagination rejects a cycle', () async {
    await expectLater(
      paginate<int>(
        load: (_) async => CursorPage<int>(items: <int>[], nextCursor: 'same'),
      ).drain<void>(),
      throwsA(isA<ZagrosException>()),
    );
  });

  test('opened raw config is redacted and wipeable', () {
    final envelope = ConfigEnvelope.fromJson(<String, Object?>{
      'v': 1,
      'alg': configEnvelopeAlgorithm,
      'application_id': 'app',
      'application_key_id': 'key',
      'signing_key_id': 'sig',
      'device_id': 'device',
      'config_id': 'config',
      'connection_id': null,
      'core_id': 'core',
      'protocol': 'vless',
      'engine': 'sing-box',
      'issued_at': 1,
      'not_before': 1,
      'expires_at': 2,
      'salt': 'salt',
      'eph': 'eph',
      'nonce': 'nonce',
      'ct': 'ciphertext',
      'signature': 'signature',
    });
    final opened = OpenedConfig(envelope: envelope, plaintext: <int>[1, 2, 3]);
    expect(opened.toString(), isNot(contains('[1, 2, 3]')));
    opened.dispose();
    expect(opened.plaintext, everyElement(0));
  });
}
