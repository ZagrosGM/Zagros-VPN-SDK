import 'dart:convert';

import '../models/config.dart';
import '../models/json.dart';
import 'json_yaml_parser.dart';
import 'openvpn_parser.dart';
import 'parser_limits.dart';
import 'uri_parser.dart';
import 'wireguard_parser.dart';

class ConfigParser {
  const ConfigParser();

  NormalizedConfig parseApplicationPayload(List<int> plaintext) {
    if (plaintext.length > maximumConfigBytes) {
      throw const FormatException('configuration exceeds size limit');
    }
    final decoded = jsonDecode(utf8.decode(plaintext, allowMalformed: false));
    enforceJsonShape(decoded);
    final root = objectMap(decoded, name: 'Application config');
    final config = requiredObject(root, 'config');
    final protocol = requiredString(config, 'protocol');
    final engine = requiredString(config, 'engine');
    final displayName = config['display_name']?.toString() ?? protocol;
    final payload = config['payload'];
    final parsed = _parsePayload(
      protocol: protocol,
      engine: engine,
      displayName: displayName,
      payload: payload,
    );
    return NormalizedConfig(
      protocol: parsed.protocol,
      engine: parsed.engine.isEmpty ? engine : parsed.engine,
      displayName: displayName,
      sourceFormat: parsed.sourceFormat,
      endpoints: parsed.endpoints,
      credentials: parsed.credentials,
      options: parsed.options,
      extensions: <String, Object?>{
        ...parsed.extensions,
        'application_metadata': <String, Object?>{
          'v': root['v'],
          'connection_id': root['connection_id'],
          'core_id': config['core_id'],
        },
        'driver_payload': normalizeJson(payload),
      },
      warnings: parsed.warnings,
    );
  }

  NormalizedConfig _parsePayload({
    required String protocol,
    required String engine,
    required String displayName,
    required Object? payload,
  }) {
    if (payload is String) {
      final trimmed = payload.trim();
      if (protocol == 'wireguard' || trimmed.startsWith('[Interface]')) {
        return parseWireGuard(trimmed, displayName: displayName);
      }
      if (protocol == 'ovpn' || protocol == 'openvpn') {
        return parseOpenVpn(trimmed, displayName: displayName);
      }
      if (trimmed.contains('://')) {
        return parseShareUri(trimmed);
      }
      if (trimmed.startsWith('{')) {
        final configs = parseSingBox(trimmed);
        if (configs.length != 1) {
          throw const FormatException('expected one runtime config');
        }
        return configs.single;
      }
    }
    final mapping = objectMap(payload, name: 'driver payload');
    rejectExternalFileReferences(mapping);

    if (mapping.containsKey('profile') && mapping['profile'] is String) {
      final profileStr = (mapping['profile'] as String).trim();
      if (protocol == 'wireguard' || profileStr.startsWith('[Interface]')) {
        return parseWireGuard(profileStr, displayName: displayName);
      }
      if (protocol == 'ovpn' || protocol == 'openvpn') {
        final parsed = parseOpenVpn(profileStr, displayName: displayName);
        final creds = Map<String, Object?>.from(parsed.credentials);
        if (mapping.containsKey('username') && mapping['username'] != null) {
          creds['username'] = mapping['username'];
        }
        if (mapping.containsKey('password') && mapping['password'] != null) {
          creds['password'] = mapping['password'];
        }
        return NormalizedConfig(
          protocol: parsed.protocol,
          engine: parsed.engine,
          displayName: parsed.displayName,
          sourceFormat: parsed.sourceFormat,
          endpoints: parsed.endpoints,
          credentials: Map<String, Object?>.unmodifiable(creds),
          options: parsed.options,
          extensions: parsed.extensions,
          warnings: parsed.warnings,
        );
      }
    }

    if (mapping.containsKey('outbounds') && mapping['outbounds'] is List) {
      final outboundsList = mapping['outbounds'] as List;
      for (final value in outboundsList) {
        if (value is Map) {
          final outbound = objectMap(value, name: 'sing-box outbound');
          final proto = outbound['type']?.toString() ?? protocol;
          final host = outbound['server'] ?? outbound['host'];
          final port = outbound['server_port'] ?? outbound['port'];
          if (host != null && port != null) {
            final credentials = <String, Object?>{};
            for (final key in <String>[
              'id',
              'uuid',
              'password',
              'username',
              'private_key',
              'preshared_key',
              'account',
              'token',
              'auth',
            ]) {
              if (outbound.containsKey(key)) credentials[key] = outbound[key];
            }
            return NormalizedConfig(
              protocol: proto.isEmpty ? protocol : proto,
              engine: engine.isEmpty ? 'sing-box' : engine,
              displayName: displayName,
              sourceFormat: ConfigSourceFormat.singBoxJson,
              endpoints: <VpnEndpoint>[
                VpnEndpoint(
                  host: validHost(host),
                  port: validPort(port),
                  transport: outbound['network']?.toString() ??
                      (outbound['transport'] is Map
                          ? (outbound['transport'] as Map)['type']?.toString()
                          : null),
                ),
              ],
              credentials: Map<String, Object?>.unmodifiable(credentials),
              options: Map<String, Object?>.unmodifiable(Map<String, Object?>.from(outbound)),
              extensions: <String, Object?>{
                'original': mapping,
                'outbound': outbound,
              },
              warnings: const <String>[],
            );
          }
        }
      }
    }

    final server = mapping['server'] ?? mapping['host'];
    final port = mapping['port'];
    final credentials = <String, Object?>{};
    for (final key in <String>[
      'id',
      'uuid',
      'password',
      'username',
      'private_key',
      'preshared_key',
      'account',
      'token',
    ]) {
      if (mapping.containsKey(key)) credentials[key] = mapping[key];
    }
    final warnings = <String>[];
    if (protocol == 'pptp') warnings.add('legacy_insecure');
    if (protocol == 'l2tp' || protocol == 'l2tp-ipsec') {
      warnings.add('platform_support_conditional');
    }
    return NormalizedConfig(
      protocol: protocol,
      engine: engine,
      displayName: displayName,
      sourceFormat: ConfigSourceFormat.fields,
      endpoints: server == null || port == null
          ? const <VpnEndpoint>[]
          : <VpnEndpoint>[
              VpnEndpoint(host: validHost(server), port: validPort(port)),
            ],
      credentials: Map<String, Object?>.unmodifiable(credentials),
      options: Map<String, Object?>.unmodifiable(mapping),
      extensions: <String, Object?>{'original': mapping},
      warnings: List<String>.unmodifiable(warnings),
    );
  }
}
