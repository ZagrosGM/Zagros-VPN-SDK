/// Live verification for the zagros-file WireGuard path (run on demand,
/// never in CI): fetch a REAL subscription, download its WireGuard markers,
/// parse them, and report redacted evidence.
///
/// Usage:
///   dart run tool/live_file_check.dart <sub-url> <device-id> [--save-wg path]
///
/// Prints statuses, counts and shapes only. The subscription token is
/// scrubbed from every line; key material is never printed. With --save-wg
/// the first WireGuard payload is written to [path] (mode 600) for a
/// follow-up `wg` handshake check — delete it afterwards.
library;

import 'dart:convert';
import 'dart:io';

import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

String _scrub(String text, String token) =>
    token.isEmpty ? text : text.replaceAll(token, '***');

Future<void> main(List<String> args) async {
  if (args.length < 2) {
    stderr.writeln(
      'usage: live_file_check.dart <sub-url> <device-id> '
      '[--save-wg path]',
    );
    exit(2);
  }
  final subUrl = args[0];
  final deviceId = args[1];
  var savePath = '';
  final saveFlag = args.indexOf('--save-wg');
  if (saveFlag >= 0 && saveFlag + 1 < args.length) {
    savePath = args[saveFlag + 1];
  }
  final uri = Uri.parse(subUrl);
  final token = uri.pathSegments.isEmpty ? '' : uri.pathSegments.last;
  String scrub(String text) => _scrub(text, token);

  final fetchClient = HttpOfficialSubscriptionClient();
  final fileClient = HttpOfficialFileDownloadClient();
  try {
    final document = await fetchClient.fetch(uri, deviceId: deviceId);
    final schemes = <String, int>{};
    for (final config in document.configs) {
      final scheme = config.normalized.protocol;
      schemes[scheme] = (schemes[scheme] ?? 0) + 1;
    }
    stdout.writeln(
      'fetch=OK links=${document.configs.length} '
      'schemes=$schemes markers=${document.fileRefs.length}',
    );
    for (final ref in document.fileRefs) {
      stdout.writeln('marker: core=${ref.coreId} tag=${ref.tag}');
    }
    final wgRefs = document.fileRefs
        .where((ref) => ref.coreId.toLowerCase() == 'wireguard')
        .toList(growable: false);
    if (wgRefs.isEmpty) {
      stdout.writeln('RESULT: no WireGuard markers (nothing to download)');
      exit(1);
    }
    var saved = false;
    for (final ref in wgRefs) {
      try {
        final content = await fileClient.fetchFile(
          subscriptionUri: uri,
          ref: ref,
          deviceId: deviceId,
        );
        final parsed = parseWireGuard(content);
        final endpoints = parsed.endpoints
            .map((e) => '${e.host}:${e.port}/${e.transport}')
            .join(',');
        stdout.writeln(
          'downloaded: core=${ref.coreId} tag=${ref.tag} '
          'bytes=${utf8.encode(content).length} '
          'protocol=${parsed.protocol} engine=${parsed.engine} '
          'display=${parsed.displayName} endpoints=$endpoints',
        );
        if (savePath.isNotEmpty && !saved) {
          final file = File(savePath);
          await file.writeAsString(content);
          await Process.run('chmod', ['600', savePath]);
          stdout.writeln(
            'saved: path=$savePath bytes='
            '${await file.length()}',
          );
          saved = true;
        }
      } catch (error) {
        stdout.writeln(
          scrub('FAILED: core=${ref.coreId} tag=${ref.tag} error=$error'),
        );
        exit(1);
      }
    }
    stdout.writeln('RESULT: OK (${wgRefs.length} WireGuard file(s))');
  } catch (error) {
    stdout.writeln(scrub('RESULT: FAIL error=$error'));
    exit(1);
  } finally {
    fetchClient.close();
    fileClient.close();
  }
}
