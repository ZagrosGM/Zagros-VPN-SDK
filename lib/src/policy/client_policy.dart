enum ClientProductMode { official, whiteLabel }

enum ClientCapability {
  applicationLogin,
  subscriptionImport,
  manualConfig,
  rawConfigDisplay,
  rawConfigExport,
  rawConfigClipboard,
  rawConfigPersistence,
}

class ClientPolicyViolation implements Exception {
  const ClientPolicyViolation(this.mode, this.capability);

  final ClientProductMode mode;
  final ClientCapability capability;

  @override
  String toString() => 'ClientPolicyViolation($mode, $capability)';
}

class ClientPolicy {
  const ClientPolicy._({
    required this.mode,
    required this.applicationLogin,
    required this.subscriptionImport,
    required this.manualConfig,
    required this.rawConfigDisplay,
    required this.rawConfigExport,
    required this.rawConfigClipboard,
    required this.rawConfigPersistence,
  });

  const ClientPolicy.official()
      : this._(
          mode: ClientProductMode.official,
          applicationLogin: false,
          subscriptionImport: true,
          manualConfig: true,
          rawConfigDisplay: true,
          rawConfigExport: true,
          rawConfigClipboard: true,
          rawConfigPersistence: true,
        );

  const ClientPolicy.whiteLabel()
      : this._(
          mode: ClientProductMode.whiteLabel,
          applicationLogin: true,
          subscriptionImport: false,
          manualConfig: false,
          rawConfigDisplay: false,
          rawConfigExport: false,
          rawConfigClipboard: false,
          rawConfigPersistence: false,
        );

  final ClientProductMode mode;
  final bool applicationLogin;
  final bool subscriptionImport;
  final bool manualConfig;
  final bool rawConfigDisplay;
  final bool rawConfigExport;
  final bool rawConfigClipboard;
  final bool rawConfigPersistence;

  bool allows(ClientCapability capability) => switch (capability) {
        ClientCapability.applicationLogin => applicationLogin,
        ClientCapability.subscriptionImport => subscriptionImport,
        ClientCapability.manualConfig => manualConfig,
        ClientCapability.rawConfigDisplay => rawConfigDisplay,
        ClientCapability.rawConfigExport => rawConfigExport,
        ClientCapability.rawConfigClipboard => rawConfigClipboard,
        ClientCapability.rawConfigPersistence => rawConfigPersistence,
      };

  void require(ClientCapability capability) {
    if (!allows(capability)) throw ClientPolicyViolation(mode, capability);
  }

  void assertWhiteLabelInvariant() {
    if (mode == ClientProductMode.whiteLabel &&
        (subscriptionImport ||
            manualConfig ||
            rawConfigDisplay ||
            rawConfigExport ||
            rawConfigClipboard ||
            rawConfigPersistence)) {
      throw StateError('White-label policy permits raw-config exposure');
    }
  }
}
