import 'dart:convert';

import '../crypto/encoding.dart';
import '../models/config.dart';
import 'parser_limits.dart';

const Set<String> _supportedSchemes = <String>{
  'vless',
  'vmess',
  'trojan',
  'ss',
  'shadowsocks',
  'hysteria2',
  'hy2',
  'tuic',
  'anytls',
  'socks',
  'socks5',
  'http',
  'https',
  'ssh',
  'pptp',
  'l2tp',
  'l2tp+ipsec',
};

NormalizedConfig parseShareUri(String input) {
  enforceTextLimit(input);
  final trimmed = input.trim();
  if (trimmed.startsWith('vmess://')) {
    return _parseVmess(trimmed);
  }
  final uri = Uri.parse(trimmed);
  final scheme = uri.scheme.toLowerCase();
  if (!_supportedSchemes.contains(scheme) || uri.host.isEmpty || !uri.hasPort) {
    throw const FormatException('unsupported or incomplete share URI');
  }
  final protocol = switch (scheme) {
    'ss' => 'shadowsocks',
    'hy2' => 'hysteria2',
    'socks5' => 'socks',
    _ => scheme,
  };
  final credentials = <String, Object?>{};
  if (uri.userInfo.isNotEmpty) {
    final decodedUserInfo = Uri.decodeComponent(uri.userInfo);
    if (protocol == 'shadowsocks') {
      _parseShadowsocksCredentials(decodedUserInfo, credentials);
    } else {
      final parts = decodedUserInfo.split(':');
      if (parts.length == 1) {
        credentials[protocol == 'vless' ? 'id' : 'password'] = parts.single;
      } else {
        credentials['username'] = parts.first;
        credentials['password'] = parts.sublist(1).join(':');
      }
    }
  }
  final query = <String, Object?>{
    for (final entry in uri.queryParametersAll.entries)
      entry.key: entry.value.length == 1 ? entry.value.single : entry.value,
  };
  return NormalizedConfig(
    protocol: protocol,
    engine: '',
    displayName:
        uri.fragment.isEmpty ? protocol : Uri.decodeComponent(uri.fragment),
    sourceFormat: ConfigSourceFormat.uri,
    endpoints: <VpnEndpoint>[
      VpnEndpoint(
        host: validHost(uri.host),
        port: validPort(uri.port),
        transport: query['type']?.toString() ?? query['transport']?.toString(),
      ),
    ],
    credentials: Map<String, Object?>.unmodifiable(credentials),
    options: Map<String, Object?>.unmodifiable(query),
    extensions: <String, Object?>{'uri': trimmed},
    warnings: <String>[
      if (protocol == 'pptp') 'legacy_insecure',
      if (protocol == 'l2tp' || protocol == 'l2tp+ipsec')
        'platform_support_conditional',
    ],
  );
}

void _parseShadowsocksCredentials(
  String userInfo,
  Map<String, Object?> credentials,
) {
  var decoded = userInfo;
  if (!decoded.contains(':')) {
    final unpadded = decoded.replaceFirst(RegExp(r'=+$'), '');
    try {
      decoded = utf8.decode(decodeBase64Url(unpadded));
    } on FormatException {
      throw const FormatException('invalid Shadowsocks credentials');
    }
  }
  final separator = decoded.indexOf(':');
  if (separator < 1 || separator == decoded.length - 1) {
    throw const FormatException('invalid Shadowsocks credentials');
  }
  credentials['method'] = decoded.substring(0, separator);
  credentials['password'] = decoded.substring(separator + 1);
}

NormalizedConfig _parseVmess(String input) {
  final encoded = input.substring('vmess://'.length).split('#').first;
  final unpadded = encoded.replaceFirst(RegExp(r'=+$'), '');
  if (encoded.substring(unpadded.length).length > 2 ||
      encoded.contains(RegExp(r'=[^=]'))) {
    throw const FormatException('invalid VMess base64');
  }
  final decoded = utf8.decode(decodeBase64Url(unpadded));
  final value = jsonDecode(decoded);
  if (value is! Map<String, Object?>) {
    throw const FormatException('invalid VMess JSON');
  }
  enforceJsonShape(value);
  final host = validHost(value['add']);
  final port = validPort(value['port']);
  final id = value['id']?.toString() ?? '';
  if (id.isEmpty) throw const FormatException('VMess UUID is missing');
  return NormalizedConfig(
    protocol: 'vmess',
    engine: '',
    displayName: value['ps']?.toString() ?? 'vmess',
    sourceFormat: ConfigSourceFormat.vmessJson,
    endpoints: <VpnEndpoint>[
      VpnEndpoint(host: host, port: port, transport: value['net']?.toString()),
    ],
    credentials: <String, Object?>{'id': id},
    options: Map<String, Object?>.unmodifiable(
      Map<String, Object?>.from(value),
    ),
    extensions: <String, Object?>{'vmess': Map<String, Object?>.from(value)},
    warnings: const <String>[],
  );
}
