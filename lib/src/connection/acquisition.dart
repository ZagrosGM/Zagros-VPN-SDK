import 'package:cryptography/cryptography.dart';

import '../api/application_api.dart';
import '../auth/session.dart';
import '../crypto/config_envelope.dart';
import '../models/application.dart';
import '../models/config.dart';
import '../models/connection.dart';
import '../models/error.dart';
import '../parsers/config_parser.dart';
import 'lifecycle.dart';

class AcquiredConfig {
  const AcquiredConfig({
    required this.selector,
    required this.opened,
    required this.normalized,
    required this.lifecycle,
  });

  final ConfigSelector selector;
  final OpenedConfig opened;
  final NormalizedConfig normalized;
  final ConnectionLifecycle lifecycle;

  void disposeRuntimeConfig() => opened.dispose();
}

typedef ConfigSelectorChooser = ConfigSelector Function(
  List<ConfigSelector> selectors,
);

class ConfigAcquisition {
  ConfigAcquisition({
    required this.api,
    required this.session,
    required this.application,
    required this.deviceKeyPair,
    this.parser = const ConfigParser(),
    this.envelopeOpener = const CryptographicConfigEnvelopeOpener(),
    this.scheduler = const TimerActionScheduler(),
    DateTime Function()? clock,
    this.maximumAttempts = 2,
  }) : clock = clock ?? DateTime.now {
    if (maximumAttempts < 1 || maximumAttempts > 3) {
      throw ArgumentError.value(maximumAttempts, 'maximumAttempts');
    }
  }

  final ApplicationApi api;
  final ApplicationSession session;
  final ApplicationIdentity application;
  final SimpleKeyPair deviceKeyPair;
  final ConfigParser parser;
  final ConfigEnvelopeOpener envelopeOpener;
  final ActionScheduler scheduler;
  final DateTime Function() clock;
  final int maximumAttempts;

  /// Each attempt is exactly: list once, select once, start/renew the selected
  /// connection, then consume that same selector without a second list call.
  Future<AcquiredConfig> acquire(ConfigSelectorChooser choose) async {
    Object? lastError;
    StackTrace? lastStack;
    var authenticationRecoveryUsed = false;
    for (var attempt = 1; attempt <= maximumAttempts; attempt += 1) {
      OpenedConfig? opened;
      try {
        final token = await session.accessToken();
        final selectors = await api.listConfigs(session.deviceId, token);
        if (selectors.isEmpty) {
          throw const ZagrosException(
            ZagrosErrorKind.protocolUnavailable,
            'No Application-mode configurations are available',
          );
        }
        final selected = choose(List<ConfigSelector>.unmodifiable(selectors));
        if (!selectors.any(
          (item) =>
              identical(item, selected) || item.configId == selected.configId,
        )) {
          throw ArgumentError(
            'chooser returned a selector outside the supplied list',
          );
        }
        final configId = selected.configId;
        if (!selected.connectable || configId == null) {
          throw const ZagrosException(
            ZagrosErrorKind.protocolUnavailable,
            'Selected configuration is not connectable',
          );
        }
        final connection = await api.startConnection(
          deviceId: session.deviceId,
          accessToken: token,
          configId: configId,
        );
        final envelope = await api.consumeConfig(
          deviceId: session.deviceId,
          accessToken: token,
          configId: configId,
        );
        _validateBindings(selected, connection, envelope);
        opened = await envelopeOpener.open(
          envelope: envelope,
          deviceKeyPair: deviceKeyPair,
          applicationConfigPublicKey: SimplePublicKey(
            application.configPublicKey,
            type: KeyPairType.x25519,
          ),
          applicationSigningPublicKey: SimplePublicKey(
            application.signingPublicKey,
            type: KeyPairType.ed25519,
          ),
          now: DateTime.fromMillisecondsSinceEpoch(
            envelope.issuedAt * 1000,
            isUtc: true,
          ),
          expectedApplicationId: application.applicationId,
          expectedDeviceId: session.deviceId,
        );
        final normalized = parser.parseApplicationPayload(opened.plaintext);
        final lifecycle = ConnectionLifecycle(
          api: api,
          session: session,
          initial: connection,
          scheduler: scheduler,
          clock: clock,
        )..start();
        return AcquiredConfig(
          selector: selected,
          opened: opened,
          normalized: normalized,
          lifecycle: lifecycle,
        );
      } catch (error, stackTrace) {
        opened?.dispose();
        lastError = error;
        lastStack = stackTrace;
        if (attempt < maximumAttempts &&
            !authenticationRecoveryUsed &&
            error is ZagrosApiException &&
            error.kind == ZagrosErrorKind.authentication) {
          authenticationRecoveryUsed = true;
          await session.accessToken(forceRefresh: true);
          continue;
        }
        if (attempt >= maximumAttempts || !_recoverableAcquisition(error)) {
          Error.throwWithStackTrace(error, stackTrace);
        }
      }
    }
    Error.throwWithStackTrace(lastError!, lastStack!);
  }

  bool _recoverableAcquisition(Object error) {
    if (error is ZagrosException &&
        (error.kind == ZagrosErrorKind.envelopeExpired ||
            error.kind == ZagrosErrorKind.transport)) {
      return true;
    }
    if (error is ZagrosApiException) {
      return const <String>{
        'config_grant_expired',
        'config_grant_consumed',
        'config_grant_invalid',
        'connection_required',
      }.contains(error.code);
    }
    return false;
  }

  void _validateBindings(
    ConfigSelector selected,
    ConnectionInfo connection,
    ConfigEnvelope envelope,
  ) {
    if (envelope.applicationKeyId != application.configKeyId ||
        envelope.signingKeyId != application.signingKeyId ||
        envelope.configId != selected.configId ||
        envelope.connectionId != connection.connectionId ||
        envelope.coreId != selected.coreId ||
        envelope.protocol != selected.protocol ||
        envelope.engine != selected.engine) {
      throw const ZagrosException(
        ZagrosErrorKind.envelopeInvalid,
        'Config envelope binding mismatch',
      );
    }
  }
}
