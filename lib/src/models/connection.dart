import 'json.dart';

enum ConnectionTarget { local, node }

enum TeardownCapability { targeted, authorizationOnly }

class ConnectionInfo {
  const ConnectionInfo({
    required this.connectionId,
    required this.coreId,
    required this.protocol,
    required this.desiredStatus,
    required this.observedStatus,
    required this.target,
    required this.teardownCapability,
    required this.notAfter,
    this.configId,
    this.renewedAt,
    this.lastObservedAt,
    this.error,
  });

  factory ConnectionInfo.fromJson(Map<String, Object?> json) {
    final target = requiredString(json, 'target');
    final teardown = requiredString(json, 'teardown_capability');
    return ConnectionInfo(
      connectionId: requiredString(json, 'connection_id'),
      configId: optionalString(json, 'config_id'),
      coreId: requiredString(json, 'core_id'),
      protocol: requiredString(json, 'protocol'),
      desiredStatus: requiredString(json, 'desired_status'),
      observedStatus: requiredString(json, 'observed_status'),
      target: switch (target) {
        'local' => ConnectionTarget.local,
        'node' => ConnectionTarget.node,
        _ => throw FormatException('unknown connection target'),
      },
      teardownCapability: switch (teardown) {
        'targeted' => TeardownCapability.targeted,
        'authorization_only' => TeardownCapability.authorizationOnly,
        _ => throw FormatException('unknown teardown capability'),
      },
      notAfter: requiredDateTime(json, 'not_after'),
      renewedAt: optionalDateTime(json, 'renewed_at'),
      lastObservedAt: optionalDateTime(json, 'last_observed_at'),
      error: optionalString(json, 'error'),
    );
  }

  final String connectionId;
  final String? configId;
  final String coreId;
  final String protocol;
  final String desiredStatus;
  final String observedStatus;
  final ConnectionTarget target;
  final TeardownCapability teardownCapability;
  final DateTime notAfter;
  final DateTime? renewedAt;
  final DateTime? lastObservedAt;
  final String? error;
}
