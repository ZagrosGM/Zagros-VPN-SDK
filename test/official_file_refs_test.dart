import 'dart:convert';

import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

const _markerOvpn =
    '# zagros-file: /sub/file/TOKEN123/openvpn/openvpn';
const _markerWg = '# zagros-file: /sub/file/TOKEN123/wireguard/wireguard';

void main() {
  group('extractFileRefs', () {
    test('finds markers in a plain body', () {
      const body = 'ss://secret@example:8388#one\n'
          '$_markerOvpn\n'
          '$_markerWg\n';
      final refs = extractFileRefs(body);
      expect(refs, hasLength(2));
      expect(refs[0].coreId, 'openvpn');
      expect(refs[0].tag, 'openvpn');
      expect(refs[0].path, '/sub/file/TOKEN123/openvpn/openvpn');
      expect(refs[1].coreId, 'wireguard');
    });

    test('decodes a base64 envelope first', () {
      const body = 'ss://secret@example:8388#one\n$_markerOvpn\n';
      final refs = extractFileRefs(base64.encode(utf8.encode(body)));
      expect(refs, hasLength(1));
      expect(refs[0].coreId, 'openvpn');
    });

    test('skips malformed markers without losing good ones', () {
      const body = '# zagros-file: https://evil.example/x\n'
          '# zagros-file: /sub/file/ok/openvpn/vpn1\n'
          '# zagros-file: /sub/file/../escape\n'
          '# zagros-file: not-a-path\n';
      final refs = extractFileRefs(body);
      expect(refs, hasLength(1));
      expect(refs[0].tag, 'vpn1');
    });

    test('decodes percent-encoded tags and rejoins slashes', () {
      const body = '# zagros-file: /sub/file/T/openvpn/my%20vpn\n'
          '# zagros-file: /sub/file/T/openvpn/a/b\n';
      final refs = extractFileRefs(body);
      expect(refs, hasLength(2));
      expect(refs[0].tag, 'my vpn');
      expect(refs[1].tag, 'a/b');
    });

    test('rejects a corrupt body with too many markers', () {
      final body = List<String>.generate(
        70,
        (i) => '# zagros-file: /sub/file/T/openvpn/vpn$i',
      ).join('\n');
      expect(() => extractFileRefs(body), throwsFormatException);
      expect(
        () => extractFileRefs(body, maximumFileRefs: 128),
        returnsNormally,
      );
    });

    test('finds nothing without markers', () {
      expect(extractFileRefs('ss://secret@example:8388#one\n'), isEmpty);
      expect(extractFileRefs(base64.encode(utf8.encode('ss://x'))), isEmpty);
    });
  });

  group('OfficialFileRef.resolve', () {
    test('resolves against the subscription origin', () {
      const ref = OfficialFileRef(
        coreId: 'openvpn',
        tag: 'openvpn',
        path: '/sub/file/TOKEN123/openvpn/openvpn',
      );
      final uri = ref.resolve(Uri.parse('https://panel.example:8443/sub/old'));
      expect(uri.toString(),
          'https://panel.example:8443/sub/file/TOKEN123/openvpn/openvpn');
    });

    test('refuses cross-origin escape', () {
      const ref = OfficialFileRef(
        coreId: 'x',
        tag: 'y',
        path: 'https://evil.example/z',
      );
      expect(() => ref.resolve(Uri.parse('https://panel.example/sub/a')),
          throwsFormatException);
    });
  });

  group('OfficialConfigParser.fileRefs', () {
    test('mirrors the top-level extractor on both envelopes', () {
      const parser = OfficialConfigParser();
      const plain = '$_markerOvpn\n';
      expect(parser.fileRefs(plain), hasLength(1));
      expect(
        parser.fileRefs(base64.encode(utf8.encode(plain))),
        hasLength(1),
      );
    });
  });
}
