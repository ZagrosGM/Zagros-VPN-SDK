import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

const _link =
    'vless://00000000-0000-0000-0000-000000000001@vpn.example:443?security=tls&type=tcp#Primary';

void main() {
  group('Official aggregate parser', () {
    const parser = OfficialConfigParser();

    test('parses merged base64 link payload and removes exact duplicates', () {
      final payload = base64.encode(utf8.encode('$_link\n$_link\n'));
      final configs = parser.parse(payload);
      expect(configs, hasLength(1));
      expect(configs.single.normalized.protocol, 'vless');
      expect(configs.single.normalized.displayName, 'Primary');
      expect(configs.single.rawText, _link);
    });

    test('auto-detects WireGuard, OpenVPN, Clash, and sing-box', () {
      final wireGuard = parser.parse('''
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = vpn.example:51820
''');
      expect(wireGuard.single.normalized.protocol, 'wireguard');

      final openVpn = parser.parse('''
client
remote vpn.example 1194 udp
<ca>
certificate
</ca>
''');
      expect(openVpn.single.normalized.protocol, 'ovpn');

      final clash = parser.parse('''
proxies:
  - name: Primary
    type: trojan
    server: vpn.example
    port: 443
    password: secret
''');
      expect(clash.single.normalized.protocol, 'trojan');

      final singBox = parser.parse(
        jsonEncode(<String, Object?>{
          'outbounds': <Object?>[
            <String, Object?>{
              'type': 'vless',
              'tag': 'Primary',
              'server': 'vpn.example',
              'server_port': 443,
              'uuid': 'id',
            },
          ],
        }),
      );
      expect(singBox.single.normalized.protocol, 'vless');
    });

    test('rejects malformed and oversized inputs', () {
      expect(() => parser.parse('not a configuration'), throwsFormatException);
      expect(
        () => parser.parse('x' * (maximumConfigBytes + 1)),
        throwsFormatException,
      );
    });
  });

  group('Official subscription transport', () {
    test('constructor enforces bounded transport settings', () {
      expect(
        () => HttpOfficialSubscriptionClient(timeout: Duration.zero),
        throwsArgumentError,
      );
      expect(
        () => HttpOfficialSubscriptionClient(maximumRedirects: 6),
        throwsArgumentError,
      );
      expect(
        () => HttpOfficialSubscriptionClient(
          maximumResponseBytes: maximumConfigBytes + 1,
        ),
        throwsArgumentError,
      );
    });

    test('sends stable device identity and parses contract metadata', () async {
      late http.Request observed;
      final client = HttpOfficialSubscriptionClient(
        client: MockClient((request) async {
          observed = request;
          return http.Response(
            base64.encode(utf8.encode(_link)),
            200,
            headers: <String, String>{
              'etag': '"catalog-v1"',
              'last-modified': 'Mon, 07 Sep 2026 10:00:00 GMT',
              'subscription-userinfo':
                  'upload=10; download=20; total=100; expire=1893456000',
              'profile-update-interval': '12',
            },
          );
        }),
      );

      final result = await client.fetch(
        Uri.parse('https://panel.example/sub/token'),
        deviceId: 'zg_stable-device-id',
      );

      expect(observed.method, 'GET');
      expect(observed.headers['x-device-id'], 'zg_stable-device-id');
      expect(observed.headers['accept'], contains('text/plain'));
      expect(observed.followRedirects, isFalse);
      expect(result.configs, hasLength(1));
      expect(result.etag, '"catalog-v1"');
      expect(result.usage?.usedBytes, 30);
      expect(result.usage?.remainingBytes, 70);
      expect(result.updateInterval, const Duration(hours: 12));
      expect(result.toString(), isNot(contains(_link)));
      client.close();
    });

    test('follows bounded same-origin redirect without leaking cross-origin',
        () async {
      final requests = <Uri>[];
      final sameOrigin = HttpOfficialSubscriptionClient(
        client: MockClient((request) async {
          requests.add(request.url);
          if (request.url.path == '/start') {
            return http.Response('', 302,
                headers: <String, String>{'location': '/next'});
          }
          expect(request.headers['x-device-id'], 'zg_stable-device-id');
          return http.Response(_link, 200);
        }),
      );
      final result = await sameOrigin.fetch(
        Uri.parse('https://panel.example/start'),
        deviceId: 'zg_stable-device-id',
      );
      expect(result.configs, hasLength(1));
      expect(requests.map((uri) => uri.path), <String>['/start', '/next']);
      sameOrigin.close();

      var calls = 0;
      final crossOrigin = HttpOfficialSubscriptionClient(
        client: MockClient((request) async {
          calls += 1;
          return http.Response(
            '',
            302,
            headers: <String, String>{
              'location': 'https://attacker.example/steal',
            },
          );
        }),
      );
      await expectLater(
        crossOrigin.fetch(
          Uri.parse('https://panel.example/start?token=secret'),
          deviceId: 'zg_stable-device-id',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.secureTransportRequired,
          ),
        ),
      );
      expect(calls, 1);
      crossOrigin.close();
    });

    test('rejects insecure URL, invalid identity, and oversized response',
        () async {
      var calls = 0;
      final client = HttpOfficialSubscriptionClient(
        maximumResponseBytes: 1024,
        client: MockClient((request) async {
          calls += 1;
          return http.Response('x' * 1025, 200);
        }),
      );

      await expectLater(
        client.fetch(
          Uri.parse('http://panel.example/sub'),
          deviceId: 'zg_stable-device-id',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.secureTransportRequired,
          ),
        ),
      );
      await expectLater(
        client.fetch(Uri.parse('https://panel.example/sub'),
            deviceId: 'bad id'),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.validation,
          ),
        ),
      );
      await expectLater(
        client.fetch(
          Uri.parse('https://panel.example/sub'),
          deviceId: 'zg_stable-device-id',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.malformedResponse,
          ),
        ),
      );
      expect(calls, 1);
      client.close();
    });

    test('maps a request timeout to a safe transport failure', () async {
      final client = HttpOfficialSubscriptionClient(
        timeout: const Duration(milliseconds: 1),
        client: MockClient((request) async {
          await Future<void>.delayed(const Duration(milliseconds: 25));
          return http.Response(_link, 200);
        }),
      );
      await expectLater(
        client.fetch(
          Uri.parse('https://panel.example/sub'),
          deviceId: 'zg_stable-device-id',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.transport,
          ),
        ),
      );
      client.close();
    });

    test('maps revocation statuses and honors conditional 304', () async {
      var status = 403;
      late http.Request observed;
      final client = HttpOfficialSubscriptionClient(
        client: MockClient((request) async {
          observed = request;
          return http.Response('', status,
              headers: <String, String>{'etag': '"v2"'});
        }),
      );
      await expectLater(
        client.fetch(
          Uri.parse('https://panel.example/sub'),
          deviceId: 'zg_stable-device-id',
        ),
        throwsA(
          isA<ZagrosException>().having(
            (error) => error.kind,
            'kind',
            ZagrosErrorKind.authorization,
          ),
        ),
      );

      status = 304;
      final result = await client.fetch(
        Uri.parse('https://panel.example/sub'),
        deviceId: 'zg_stable-device-id',
        etag: '"v1"',
        lastModified: 'Sun, 06 Sep 2026 10:00:00 GMT',
      );
      expect(observed.headers['if-none-match'], '"v1"');
      expect(observed.headers['if-modified-since'], isNotEmpty);
      expect(result.notModified, isTrue);
      expect(result.configs, isEmpty);
      expect(result.etag, '"v2"');
      client.close();
    });
  });
}
