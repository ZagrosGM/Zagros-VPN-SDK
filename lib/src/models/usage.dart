import 'json.dart';

class UsageSummary {
  const UsageSummary({
    required this.usedBytes,
    required this.uplinkBytes,
    required this.downlinkBytes,
    required this.activeConnections,
    required this.asOf,
    this.dataLimitBytes,
    this.remainingBytes,
    this.expiresAt,
  });

  factory UsageSummary.fromJson(Map<String, Object?> json) => UsageSummary(
        usedBytes: requiredInt(json, 'used_bytes'),
        uplinkBytes: requiredInt(json, 'uplink_bytes'),
        downlinkBytes: requiredInt(json, 'downlink_bytes'),
        dataLimitBytes: optionalInt(json, 'data_limit_bytes'),
        remainingBytes: optionalInt(json, 'remaining_bytes'),
        expiresAt: optionalDateTime(json, 'expire_at'),
        activeConnections: requiredInt(json, 'active_connections'),
        asOf: requiredDateTime(json, 'as_of'),
      );

  final int usedBytes;
  final int uplinkBytes;
  final int downlinkBytes;
  final int? dataLimitBytes;
  final int? remainingBytes;
  final DateTime? expiresAt;
  final int activeConnections;
  final DateTime asOf;
}

class UsageBucket {
  const UsageBucket({
    required this.start,
    required this.end,
    required this.uplinkBytes,
    required this.downlinkBytes,
    required this.totalBytes,
  });

  factory UsageBucket.fromJson(Map<String, Object?> json) => UsageBucket(
        start: requiredDateTime(json, 'start'),
        end: requiredDateTime(json, 'end'),
        uplinkBytes: requiredInt(json, 'uplink_bytes'),
        downlinkBytes: requiredInt(json, 'downlink_bytes'),
        totalBytes: requiredInt(json, 'total_bytes'),
      );

  final DateTime start;
  final DateTime end;
  final int uplinkBytes;
  final int downlinkBytes;
  final int totalBytes;
}

class UsageHistoryPage {
  UsageHistoryPage({
    required this.granularity,
    required this.from,
    required this.to,
    required List<UsageBucket> items,
    this.nextCursor,
  }) : items = List<UsageBucket>.unmodifiable(items);

  factory UsageHistoryPage.fromJson(Map<String, Object?> json) =>
      UsageHistoryPage(
        granularity: requiredString(json, 'granularity'),
        from: requiredDateTime(json, 'from_time'),
        to: requiredDateTime(json, 'to_time'),
        items: requiredList(json, 'items')
            .map((Object? value) => UsageBucket.fromJson(objectMap(value)))
            .toList(growable: false),
        nextCursor: optionalString(json, 'next_cursor'),
      );

  final String granularity;
  final DateTime from;
  final DateTime to;
  final List<UsageBucket> items;
  final String? nextCursor;
}
