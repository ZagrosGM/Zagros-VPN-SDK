import 'dart:async';

import '../api/application_api.dart';
import '../auth/session.dart';
import '../models/connection.dart';
import '../models/error.dart';

abstract interface class ScheduledAction {
  void cancel();
}

abstract interface class ActionScheduler {
  ScheduledAction schedule(Duration delay, void Function() action);
}

class TimerActionScheduler implements ActionScheduler {
  const TimerActionScheduler();

  @override
  ScheduledAction schedule(Duration delay, void Function() action) =>
      _TimerAction(Timer(delay, action));
}

class _TimerAction implements ScheduledAction {
  const _TimerAction(this.timer);
  final Timer timer;

  @override
  void cancel() => timer.cancel();
}

class ConnectionLifecycle {
  ConnectionLifecycle({
    required this.api,
    required this.session,
    required ConnectionInfo initial,
    this.scheduler = const TimerActionScheduler(),
    DateTime Function()? clock,
    this.onChanged,
    this.onRenewalError,
  })  : _connection = initial,
        clock = clock ?? DateTime.now;

  final ApplicationApi api;
  final ApplicationSession session;
  final ActionScheduler scheduler;
  final DateTime Function() clock;
  final void Function(ConnectionInfo connection)? onChanged;
  final void Function(Object error, StackTrace stackTrace)? onRenewalError;
  ConnectionInfo _connection;
  ScheduledAction? _scheduled;
  bool _closed = false;
  bool _renewing = false;
  int _consecutiveFailures = 0;

  ConnectionInfo get connection => _connection;

  void start() {
    if (_closed) throw StateError('connection lifecycle is closed');
    _scheduleForLease();
  }

  void _scheduleForLease() {
    _scheduled?.cancel();
    final remaining = _connection.notAfter.difference(clock().toUtc());
    final leadSeconds = (remaining.inSeconds ~/ 3).clamp(20, 60);
    var delay = remaining - Duration(seconds: leadSeconds);
    if (delay.isNegative) delay = Duration.zero;
    _scheduled = scheduler.schedule(delay, () {
      unawaited(_renew());
    });
  }

  Future<void> _renew() async {
    if (_closed || _renewing) return;
    _renewing = true;
    try {
      final statuses = await _requestRenewal();
      if (statuses.isEmpty) {
        throw const ZagrosException(
          ZagrosErrorKind.connectionNotFound,
          'Active connection disappeared during renewal',
        );
      }
      _connection = statuses.single;
      _consecutiveFailures = 0;
      onChanged?.call(_connection);
      if (!_closed) _scheduleForLease();
    } catch (error, stackTrace) {
      _consecutiveFailures += 1;
      onRenewalError?.call(error, stackTrace);
      if (!_closed && _isTransientRenewalFailure(error)) {
        final remaining = _connection.notAfter.difference(clock().toUtc());
        if (remaining.isNegative) return;
        final defaultBackoff = switch (_consecutiveFailures) {
          1 => const Duration(seconds: 2),
          2 => const Duration(seconds: 5),
          _ => const Duration(seconds: 10),
        };
        final requestedBackoff = error is ZagrosApiException
            ? error.retryAfter ?? defaultBackoff
            : defaultBackoff;
        final beforeExpiry = remaining > const Duration(seconds: 2)
            ? remaining - const Duration(seconds: 2)
            : Duration.zero;
        _scheduled = scheduler.schedule(
          requestedBackoff < beforeExpiry ? requestedBackoff : beforeExpiry,
          () => unawaited(_renew()),
        );
      } else {
        _closed = true;
      }
    } finally {
      _renewing = false;
    }
  }

  bool _isTransientRenewalFailure(Object error) {
    if (error is ZagrosTransportException) return true;
    if (error is ZagrosApiException) {
      return error.statusCode == 429 || error.statusCode >= 500;
    }
    return false;
  }

  Future<List<ConnectionInfo>> _requestRenewal() async {
    var token = await session.accessToken();
    try {
      return await api.connectionStatus(
        deviceId: session.deviceId,
        accessToken: token,
        connectionId: _connection.connectionId,
        renew: true,
      );
    } on ZagrosApiException catch (error) {
      if (error.kind != ZagrosErrorKind.authentication) rethrow;
      token = await session.accessToken(forceRefresh: true);
      return api.connectionStatus(
        deviceId: session.deviceId,
        accessToken: token,
        connectionId: _connection.connectionId,
        renew: true,
      );
    }
  }

  Future<void> stop() async {
    if (_closed) return;
    _closed = true;
    _scheduled?.cancel();
    final token = await session.accessToken();
    _connection = await api.stopConnection(
      deviceId: session.deviceId,
      accessToken: token,
      connectionId: _connection.connectionId,
    );
    onChanged?.call(_connection);
  }

  void detach() {
    _closed = true;
    _scheduled?.cancel();
  }
}
