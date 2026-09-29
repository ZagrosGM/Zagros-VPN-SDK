import 'dart:convert';

import 'package:yaml/yaml.dart';

import '../models/config.dart';
import '../models/json.dart';
import 'parser_limits.dart';

List<NormalizedConfig> parseSingBox(String input) {
  enforceTextLimit(input);
  final decoded = jsonDecode(input);
  enforceJsonShape(decoded);
  final root = objectMap(decoded, name: 'sing-box config');
  rejectExternalFileReferences(root);
  final outbounds = root['outbounds'];
  if (outbounds is! List<Object?>) {
    throw const FormatException('sing-box outbounds are missing');
  }
  final configs = <NormalizedConfig>[];
  for (final value in outbounds) {
    final outbound = objectMap(value, name: 'sing-box outbound');
    final protocol = outbound['type']?.toString() ?? '';
    final host = outbound['server'];
    final port = outbound['server_port'];
    if (protocol.isEmpty) {
      throw const FormatException('sing-box outbound type is missing');
    }
    if (host == null || port == null) {
      if (const <String>{
        'direct',
        'block',
        'dns',
        'selector',
        'urltest',
      }.contains(protocol)) {
        continue;
      }
      throw const FormatException('incomplete sing-box outbound');
    }
    configs.add(
      _fromMapping(
        protocol: protocol,
        engine: 'sing-box',
        displayName: outbound['tag']?.toString() ?? protocol,
        mapping: outbound,
        host: host,
        port: port,
        format: ConfigSourceFormat.singBoxJson,
        document: root,
      ),
    );
  }
  if (configs.isEmpty) {
    throw const FormatException('sing-box has no connectable outbounds');
  }
  return List<NormalizedConfig>.unmodifiable(configs);
}

List<NormalizedConfig> parseClash(String input) {
  enforceTextLimit(input);
  final yaml = loadYaml(input);
  final normalized = normalizeJson(yaml);
  enforceJsonShape(normalized);
  final root = objectMap(normalized, name: 'Clash config');
  rejectExternalFileReferences(root);
  final proxies = root['proxies'];
  if (proxies is! List<Object?>) {
    throw const FormatException('Clash proxies are missing');
  }
  return proxies.map((Object? value) {
    final proxy = objectMap(value, name: 'Clash proxy');
    final protocol = proxy['type']?.toString() ?? '';
    if (protocol.isEmpty) {
      throw const FormatException('Clash proxy type is missing');
    }
    return _fromMapping(
      protocol: protocol,
      engine: 'clash',
      displayName: proxy['name']?.toString() ?? protocol,
      mapping: proxy,
      host: proxy['server'],
      port: proxy['port'],
      format: ConfigSourceFormat.clashYaml,
      document: root,
    );
  }).toList(growable: false);
}

NormalizedConfig _fromMapping({
  required String protocol,
  required String engine,
  required String displayName,
  required Map<String, Object?> mapping,
  required Object? host,
  required Object? port,
  required ConfigSourceFormat format,
  required Map<String, Object?> document,
}) {
  final credentials = <String, Object?>{};
  for (final key in <String>[
    'uuid',
    'id',
    'password',
    'username',
    'private_key',
    'token',
    'auth_str',
  ]) {
    if (mapping.containsKey(key)) credentials[key] = mapping[key];
  }
  return NormalizedConfig(
    protocol: protocol,
    engine: engine,
    displayName: displayName,
    sourceFormat: format,
    endpoints: <VpnEndpoint>[
      VpnEndpoint(
        host: validHost(host),
        port: validPort(port),
        transport:
            mapping['network']?.toString() ?? mapping['transport']?.toString(),
      ),
    ],
    credentials: Map<String, Object?>.unmodifiable(credentials),
    options: Map<String, Object?>.unmodifiable(
      Map<String, Object?>.from(mapping),
    ),
    extensions: <String, Object?>{
      'original': Map<String, Object?>.from(mapping),
      'document': Map<String, Object?>.from(document),
    },
    warnings: const <String>[],
  );
}
