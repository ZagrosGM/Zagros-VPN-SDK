import '../models/config.dart';
import 'parser_limits.dart';

const Set<String> _unsafeDirectives = <String>{
  'up',
  'down',
  'route-up',
  'ipchange',
  'client-connect',
  'client-disconnect',
  'learn-address',
  'auth-user-pass-verify',
  'tls-verify',
  'plugin',
  'script-security',
};
const Set<String> _inlineCapable = <String>{
  'ca',
  'cert',
  'key',
  'tls-auth',
  'tls-crypt',
  'tls-crypt-v2',
  'secret',
  'pkcs12',
  'dh',
  'crl-verify',
  'extra-certs',
  'auth-gen-token-secret',
};

NormalizedConfig parseOpenVpn(String input, {String displayName = 'OpenVPN'}) {
  enforceTextLimit(input);
  final lines = input.split(RegExp(r'\r?\n'));
  final remotes = <VpnEndpoint>[];
  final options = <String, Object?>{};
  final inlineBlocks = <String, String>{};
  String? activeTag;
  StringBuffer? activeContent;
  for (final original in lines) {
    final line = original.trim();
    if (activeTag != null) {
      if (line == '</$activeTag>') {
        inlineBlocks[activeTag] = activeContent.toString();
        activeTag = null;
        activeContent = null;
      } else {
        activeContent!.writeln(original);
      }
      continue;
    }
    if (line.startsWith('<') && line.endsWith('>') && !line.startsWith('</')) {
      final tag =
          line.substring(1, line.length - 1).split(' ').first.toLowerCase();
      if (!_inlineCapable.contains(tag) || inlineBlocks.containsKey(tag)) {
        throw FormatException(
          'unsupported or duplicate OpenVPN inline block: $tag',
        );
      }
      activeTag = tag;
      activeContent = StringBuffer();
      continue;
    }
    if (line.startsWith('</')) {
      throw const FormatException('unmatched OpenVPN inline closing tag');
    }
    if (line.isEmpty || line.startsWith('#') || line.startsWith(';')) {
      continue;
    }
    final parts = line.split(RegExp(r'\s+'));
    final directive = parts.first.toLowerCase();
    if (_unsafeDirectives.contains(directive)) {
      throw FormatException('unsafe OpenVPN directive: $directive');
    }
    if (_inlineCapable.contains(directive) && parts.length > 1) {
      throw FormatException('external OpenVPN file reference: $directive');
    }
    if (directive == 'auth-user-pass' && parts.length > 1) {
      throw const FormatException('external auth-user-pass file is forbidden');
    }
    if (directive == 'remote') {
      if (parts.length < 3) {
        throw const FormatException('invalid OpenVPN remote');
      }
      remotes.add(
        VpnEndpoint(
          host: validHost(parts[1]),
          port: validPort(parts[2]),
          transport: parts.length > 3 ? parts[3].toLowerCase() : null,
        ),
      );
    } else {
      final value = parts.length == 1 ? true : parts.sublist(1).join(' ');
      final previous = options[directive];
      options[directive] = previous == null
          ? value
          : previous is List<Object?>
              ? <Object?>[...previous, value]
              : <Object?>[previous, value];
    }
  }
  if (activeTag != null) {
    throw FormatException('unclosed OpenVPN inline block: $activeTag');
  }
  if (remotes.isEmpty) {
    throw const FormatException('OpenVPN remote is missing');
  }
  if (!inlineBlocks.containsKey('ca')) {
    throw const FormatException('inline OpenVPN CA is required');
  }
  return NormalizedConfig(
    protocol: 'ovpn',
    engine: 'openvpn',
    displayName: displayName,
    sourceFormat: ConfigSourceFormat.openVpn,
    endpoints: List<VpnEndpoint>.unmodifiable(remotes),
    credentials: const <String, Object?>{},
    options: Map<String, Object?>.unmodifiable(options),
    extensions: <String, Object?>{
      'profile': input,
      'inline_blocks': Map<String, String>.unmodifiable(inlineBlocks),
    },
    warnings: const <String>[],
  );
}
