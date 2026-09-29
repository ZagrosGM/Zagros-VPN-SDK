import 'dart:convert';

import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

void main() {
  test('URI parser keeps protocol extensions', () {
    final config = parseShareUri(
      'vless://id@example.com:443?type=ws&security=tls&x-extra=kept#Primary',
    );
    expect(config.protocol, 'vless');
    expect(config.endpoints.single.host, 'example.com');
    expect(config.credentials['id'], 'id');
    expect(config.options['x-extra'], 'kept');
    expect(config.extensions['uri'], contains('x-extra=kept'));
  });

  test('URI parser correctly normalizes VLESS Reality links with flow and pbk', () {
    final config = parseShareUri(
      'vless://a0000000-0000-0000-0000-000000000001@109.248.161.249:9443?security=reality&sni=www.google.com&fp=chrome&pbk=eYNFrun6PN4T7eeCL9PNkkkqvU50V7YdE8vql3rlc1s&sid=12345678&flow=xtls-rprx-vision&type=tcp#VPS-Reality',
    );
    expect(config.protocol, 'vless');
    expect(config.endpoints.single.host, '109.248.161.249');
    expect(config.endpoints.single.port, 9443);
    expect(config.credentials['id'], 'a0000000-0000-0000-0000-000000000001');
    expect(config.options['security'], 'reality');
    expect(config.options['sni'], 'www.google.com');
    expect(config.options['fp'], 'chrome');
    expect(config.options['pbk'], 'eYNFrun6PN4T7eeCL9PNkkkqvU50V7YdE8vql3rlc1s');
    expect(config.options['sid'], '12345678');
    expect(config.options['flow'], 'xtls-rprx-vision');
    expect(config.displayName, 'VPS-Reality');
  });

  test('VMess parser accepts padded base64 and preserves original fields', () {
    final value = base64Url.encode(
      utf8.encode(
        jsonEncode(<String, Object?>{
          'v': '2',
          'ps': 'Vector',
          'add': 'vpn.example',
          'port': '443',
          'id': '00000000-0000-0000-0000-000000000001',
          'net': 'ws',
          'future_extension': <String, Object?>{'kept': true},
        }),
      ),
    );
    final config = parseShareUri('vmess://$value');
    expect(config.protocol, 'vmess');
    expect(config.options['future_extension'], isA<Map<Object?, Object?>>());
  });

  test('Shadowsocks and legacy URI representations are normalized', () {
    final encoded = base64Url.encode(utf8.encode('aes-256-gcm:secret'));
    final shadowsocks = parseShareUri('ss://$encoded@vpn.example:8388#SS');
    expect(shadowsocks.credentials['method'], 'aes-256-gcm');
    expect(shadowsocks.credentials['password'], 'secret');

    final pptp = parseShareUri('pptp://alice:secret@vpn.example:1723');
    expect(pptp.warnings, contains('legacy_insecure'));
    final l2tp = parseShareUri('l2tp+ipsec://alice:secret@vpn.example:1701');
    expect(l2tp.warnings, contains('platform_support_conditional'));
  });

  test('WireGuard requires inline keys and endpoint', () {
    final config = parseWireGuard('''
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0
FutureField = kept
[Peer]
PublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Endpoint = backup.example:51821
AllowedIPs = 10.0.0.0/8
''');
    expect(config.protocol, 'wireguard');
    expect(config.endpoints, hasLength(2));
    expect(config.endpoints.first.port, 51820);
    expect(config.endpoints.last.host, 'backup.example');
    expect(config.credentials['private_key'], startsWith('AAAA'));
    final peers = config.extensions['peers']! as List<Object?>;
    expect((peers.first as Map<String, Object?>)['futurefield'], 'kept');
  });

  test(
    'OpenVPN accepts inline material and rejects external files/scripts',
    () {
      final config = parseOpenVpn('''
client
remote vpn.example 1194 udp
<ca>
certificate-data
</ca>
<cert>
client-cert
</cert>
<key>
client-key
</key>
''');
      expect(config.protocol, 'ovpn');
      expect(config.endpoints.single.transport, 'udp');
      final inline =
          config.extensions['inline_blocks']! as Map<String, Object?>;
      expect(inline['cert'], contains('client-cert'));
      expect(
        () => parseOpenVpn('client\nremote vpn.example 1194\nca /tmp/ca.crt'),
        throwsFormatException,
      );
      expect(
        () => parseOpenVpn(
          'client\nremote vpn.example 1194\nscript-security 2\n<ca>\nx\n</ca>',
        ),
        throwsFormatException,
      );
    },
  );

  test('Clash and sing-box enforce shape and preserve unknown fields', () {
    final clash = parseClash('''
proxies:
  - name: Primary
    type: trojan
    server: vpn.example
    port: 443
    password: secret
    future-field: kept
''').single;
    expect(clash.options['future-field'], 'kept');

    final singBox = parseSingBox(
      jsonEncode(<String, Object?>{
        'outbounds': <Object?>[
          <String, Object?>{
            'type': 'vless',
            'tag': 'Primary',
            'server': 'vpn.example',
            'server_port': 443,
            'uuid': 'id',
            'future_field': 'kept',
          },
        ],
      }),
    ).single;
    expect(singBox.options['future_field'], 'kept');
  });

  test('JSON/YAML and driver payload file references fail closed', () {
    expect(
      () => parseSingBox(
        jsonEncode(<String, Object?>{
          'outbounds': <Object?>[
            <String, Object?>{
              'type': 'vless',
              'server': 'vpn.example',
              'server_port': 443,
              'tls': <String, Object?>{'certificate_path': '/tmp/ca.pem'},
            },
          ],
        }),
      ),
      throwsFormatException,
    );
  });

  test('application field payload supports SSH and legacy warnings', () {
    const parser = ConfigParser();
    final ssh = parser.parseApplicationPayload(
      utf8.encode(
        jsonEncode(<String, Object?>{
          'v': 1,
          'connection_id': 'connection-1',
          'config': <String, Object?>{
            'core_id': 'ssh',
            'protocol': 'ssh',
            'engine': 'ssh',
            'display_name': 'SSH',
            'payload': <String, Object?>{
              'host': 'vpn.example',
              'port': 22,
              'username': 'alice',
              'password': 'secret',
              'driver_extension': 'kept',
            },
          },
        }),
      ),
    );
    expect(ssh.protocol, 'ssh');
    expect(ssh.endpoints.single.port, 22);
    expect(ssh.options['driver_extension'], 'kept');

    final pptp = parser.parseApplicationPayload(
      utf8.encode(
        jsonEncode(<String, Object?>{
          'v': 1,
          'config': <String, Object?>{
            'core_id': 'pptp',
            'protocol': 'pptp',
            'engine': 'native',
            'display_name': 'Legacy',
            'payload': <String, Object?>{
              'host': 'vpn.example',
              'port': 1723,
              'username': 'alice',
              'password': 'secret',
            },
          },
        }),
      ),
    );
    expect(pptp.warnings, contains('legacy_insecure'));

    final vlessApp = parser.parseApplicationPayload(
      utf8.encode(
        jsonEncode(<String, Object?>{
          'v': 1,
          'connection_id': 'connection-vless-1',
          'config': <String, Object?>{
            'core_id': 'xray',
            'protocol': 'vless',
            'engine': 'sing-box',
            'display_name': 'Zagros [VLESS - ws]',
            'payload': <String, Object?>{
              'outbounds': <Object?>[
                <String, Object?>{
                  'type': 'vless',
                  'tag': 'proxy',
                  'server': '109.248.161.249',
                  'server_port': 443,
                  'uuid': '43924c53-b40b-4dc8-a831-c4d32a9e2db3',
                  'tls': <String, Object?>{
                    'enabled': true,
                    'server_name': 'panel.example.com',
                  },
                  'transport': <String, Object?>{
                    'type': 'ws',
                    'path': '/ws',
                  },
                },
              ],
            },
          },
        }),
      ),
    );
    expect(vlessApp.protocol, 'vless');
    expect(vlessApp.endpoints.single.host, '109.248.161.249');
    expect(vlessApp.endpoints.single.port, 443);
    expect(vlessApp.credentials['uuid'], '43924c53-b40b-4dc8-a831-c4d32a9e2db3');
    expect(vlessApp.extensions['outbound'], isA<Map<String, Object?>>());
  });

  test('white-label policy forbids every raw-config escape', () {
    const whiteLabel = ClientPolicy.whiteLabel();
    whiteLabel.assertWhiteLabelInvariant();
    expect(whiteLabel.applicationLogin, isTrue);
    expect(whiteLabel.rawConfigDisplay, isFalse);
    expect(whiteLabel.rawConfigPersistence, isFalse);
    expect(
      () => whiteLabel.require(ClientCapability.rawConfigDisplay),
      throwsA(isA<ClientPolicyViolation>()),
    );

    const official = ClientPolicy.official();
    expect(official.manualConfig, isTrue);
    expect(official.subscriptionImport, isTrue);
  });

  test('size and depth limits fail closed', () {
    expect(
      () => parseShareUri(
        'vless://id@example.com:443?x=${'a' * maximumConfigBytes}',
      ),
      throwsFormatException,
    );
    Object? nestedValue = 'leaf';
    for (var index = 0; index < maximumNestingDepth + 2; index += 1) {
      nestedValue = <String, Object?>{'x': nestedValue};
    }
    expect(() => enforceJsonShape(nestedValue), throwsFormatException);
  });
}
