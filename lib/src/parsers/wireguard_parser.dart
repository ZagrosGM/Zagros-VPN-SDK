import '../models/config.dart';
import 'parser_limits.dart';

NormalizedConfig parseWireGuard(
  String input, {
  String displayName = 'WireGuard',
}) {
  enforceTextLimit(input);
  Map<String, Object?>? interface;
  final peers = <Map<String, Object?>>[];
  Map<String, Object?>? current;
  for (final original in input.split(RegExp(r'\r?\n'))) {
    final line = original.trim();
    if (line.isEmpty || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }
    if (line.startsWith('[') && line.endsWith(']')) {
      final section = line.substring(1, line.length - 1).toLowerCase();
      if (section == 'interface') {
        if (interface != null) {
          throw const FormatException('duplicate WireGuard Interface');
        }
        interface = <String, Object?>{};
        current = interface;
      } else if (section == 'peer') {
        current = <String, Object?>{};
        peers.add(current);
      } else {
        throw FormatException('unsupported WireGuard section: $section');
      }
      continue;
    }
    final equals = line.indexOf('=');
    if (current == null || equals <= 0) {
      throw const FormatException('invalid WireGuard INI');
    }
    final key = line.substring(0, equals).trim().toLowerCase();
    final value = line.substring(equals + 1).trim();
    final previous = current[key];
    current[key] = previous == null
        ? value
        : previous is List<Object?>
            ? <Object?>[...previous, value]
            : <Object?>[previous, value];
  }
  if (interface == null || peers.isEmpty) {
    throw const FormatException('WireGuard Interface/Peer is required');
  }
  final privateKey = interface['privatekey']?.toString() ?? '';
  if (privateKey.length < 40) {
    throw const FormatException('WireGuard private key is invalid');
  }
  final endpoints = <VpnEndpoint>[];
  for (final peer in peers) {
    final publicKey = peer['publickey']?.toString() ?? '';
    if (publicKey.length < 40) {
      throw const FormatException('WireGuard peer public key is invalid');
    }
    final endpoint = peer['endpoint']?.toString() ?? '';
    final split = endpoint.lastIndexOf(':');
    if (split <= 0) {
      throw const FormatException('WireGuard endpoint is invalid');
    }
    final host = endpoint.startsWith('[')
        ? endpoint.substring(1, endpoint.lastIndexOf(']'))
        : endpoint.substring(0, split);
    endpoints.add(
      VpnEndpoint(
        host: validHost(host),
        port: validPort(endpoint.substring(split + 1)),
        transport: 'udp',
      ),
    );
  }
  return NormalizedConfig(
    protocol: 'wireguard',
    engine: 'wireguard',
    displayName: displayName,
    sourceFormat: ConfigSourceFormat.wireGuardIni,
    endpoints: List<VpnEndpoint>.unmodifiable(endpoints),
    credentials: <String, Object?>{'private_key': privateKey},
    options: <String, Object?>{
      'address': interface['address'],
      'dns': interface['dns'],
      'peers': peers,
    },
    extensions: <String, Object?>{'interface': interface, 'peers': peers},
    warnings: const <String>[],
  );
}
