import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:zagros_vpn_sdk/zagros_vpn_sdk.dart';

class MemoryTokenStore implements SecureTokenStore {
  String? value;

  @override
  Future<void> delete() async => value = null;

  @override
  Future<String?> read() async => value;

  @override
  Future<void> write(String serializedTokens) async => value = serializedTokens;
}

class RejectingTransport implements ApiTransport {
  @override
  Future<ApiResponse> send(ApiRequest request) =>
      throw StateError('transport should not be called');
}

class ManualAction implements ScheduledAction {
  ManualAction(this.delay, this.action);
  final Duration delay;
  final void Function() action;
  bool cancelled = false;

  @override
  void cancel() => cancelled = true;

  void fire() {
    if (!cancelled) action();
  }
}

class ManualScheduler implements ActionScheduler {
  final List<ManualAction> actions = <ManualAction>[];

  @override
  ScheduledAction schedule(Duration delay, void Function() action) {
    final scheduled = ManualAction(delay, action);
    actions.add(scheduled);
    return scheduled;
  }
}

class FakeEnvelopeOpener implements ConfigEnvelopeOpener {
  int calls = 0;
  bool expireFirst = false;

  @override
  Future<OpenedConfig> open({
    required ConfigEnvelope envelope,
    required SimpleKeyPair deviceKeyPair,
    required SimplePublicKey applicationConfigPublicKey,
    required SimplePublicKey applicationSigningPublicKey,
    required DateTime now,
    required String expectedApplicationId,
    required String expectedDeviceId,
  }) async {
    calls += 1;
    if (expireFirst && calls == 1) {
      throw const ZagrosException(
        ZagrosErrorKind.envelopeExpired,
        'expired in transit',
      );
    }
    return OpenedConfig(
      envelope: envelope,
      plaintext: utf8.encode(
        jsonEncode(<String, Object?>{
          'v': 1,
          'connection_id': envelope.connectionId,
          'config': <String, Object?>{
            'core_id': envelope.coreId,
            'protocol': envelope.protocol,
            'engine': envelope.engine,
            'display_name': 'Primary',
            'payload': <String, Object?>{
              'host': 'vpn.example',
              'port': 443,
              'id': 'runtime-id',
            },
          },
        }),
      ),
    );
  }
}

class FakeApplicationApi extends ApplicationApi {
  FakeApplicationApi({
    required super.executor,
    required super.deviceIdentity,
    required this.now,
  });

  final DateTime now;
  final List<String> calls = <String>[];
  int listCount = 0;
  int refreshCount = 0;
  bool grantExpiresOnFirstConsume = false;
  bool grantAlwaysExpires = false;
  bool transportFailsOnFirstConsume = false;
  bool unauthorizedOnFirstList = false;
  Object? renewalError;
  ConnectionInfo? lastRenewed;

  @override
  Future<List<ConfigSelector>> listConfigs(
    String deviceId,
    String accessToken,
  ) async {
    listCount += 1;
    calls.add('list:$listCount');
    if (unauthorizedOnFirstList && listCount == 1) {
      throw ZagrosApiException(
        statusCode: 401,
        code: 'authentication_failed',
        message: 'expired access token',
      );
    }
    return <ConfigSelector>[
      ConfigSelector(
        configId: 'selector-$listCount',
        coreId: 'xray',
        protocol: 'vless',
        engine: 'sing-box',
        displayName: 'Primary',
        status: 'active',
        expiresAt: now.add(const Duration(seconds: 60)),
      ),
    ];
  }

  @override
  Future<ConnectionInfo> startConnection({
    required String deviceId,
    required String accessToken,
    required String configId,
  }) async {
    calls.add('start:$configId');
    return connection(configId, now.add(const Duration(seconds: 120)));
  }

  @override
  Future<ConfigEnvelope> consumeConfig({
    required String deviceId,
    required String accessToken,
    required String configId,
  }) async {
    calls.add('consume:$configId');
    if (transportFailsOnFirstConsume && listCount == 1) {
      throw const ZagrosTransportException('connection reset');
    }
    if (grantAlwaysExpires || grantExpiresOnFirstConsume && listCount == 1) {
      throw ZagrosApiException(
        statusCode: 410,
        code: 'config_grant_expired',
        message: 'expired',
      );
    }
    return envelope(configId, 'connection-$configId');
  }

  @override
  Future<List<ConnectionInfo>> connectionStatus({
    required String deviceId,
    required String accessToken,
    String? connectionId,
    bool renew = false,
  }) async {
    calls.add('renew:$connectionId:$renew');
    if (renewalError != null) throw renewalError!;
    lastRenewed = connection(
      connectionId!.substring('connection-'.length),
      now.add(const Duration(seconds: 240)),
    );
    return <ConnectionInfo>[lastRenewed!];
  }

  @override
  Future<ConnectionInfo> stopConnection({
    required String deviceId,
    required String accessToken,
    required String connectionId,
  }) async {
    calls.add('stop:$connectionId');
    return connection(
      connectionId.substring('connection-'.length),
      now,
      desired: 'stopped',
      observed: 'stopped',
    );
  }

  @override
  Future<AuthTokens> refresh({
    required String deviceId,
    required String refreshToken,
  }) async {
    refreshCount += 1;
    await Future<void>.delayed(Duration.zero);
    return tokens(now, accessToken: 'refreshed');
  }

  ConnectionInfo connection(
    String configId,
    DateTime notAfter, {
    String desired = 'connected',
    String observed = 'connected',
  }) =>
      ConnectionInfo.fromJson(<String, Object?>{
        'connection_id': 'connection-$configId',
        'config_id': configId,
        'core_id': 'xray',
        'protocol': 'vless',
        'desired_status': desired,
        'observed_status': observed,
        'target': 'node',
        'teardown_capability': 'targeted',
        'not_after': notAfter.toUtc().toIso8601String(),
        'renewed_at': now.toUtc().toIso8601String(),
        'last_observed_at': now.toUtc().toIso8601String(),
        'error': null,
      });

  ConfigEnvelope envelope(String configId, String connectionId) =>
      ConfigEnvelope.fromJson(<String, Object?>{
        'v': 1,
        'alg': configEnvelopeAlgorithm,
        'application_id': 'application-1',
        'application_key_id': 'config-key-1',
        'signing_key_id': 'signing-key-1',
        'device_id': 'device-1',
        'config_id': configId,
        'connection_id': connectionId,
        'core_id': 'xray',
        'protocol': 'vless',
        'engine': 'sing-box',
        'issued_at': now.millisecondsSinceEpoch ~/ 1000,
        'not_before': now.millisecondsSinceEpoch ~/ 1000,
        'expires_at':
            now.add(const Duration(seconds: 30)).millisecondsSinceEpoch ~/ 1000,
        'salt': 'ignored',
        'eph': 'ignored',
        'nonce': 'ignored',
        'ct': 'ignored',
        'signature': 'ignored',
      });
}

AuthTokens tokens(DateTime now, {String accessToken = 'access'}) =>
    AuthTokens.fromJson(<String, Object?>{
      'access_token': accessToken,
      'access_expires_at':
          now.add(const Duration(minutes: 5)).toUtc().toIso8601String(),
      'refresh_token': 'refresh-token-with-sufficient-test-length',
      'refresh_expires_at':
          now.add(const Duration(hours: 1)).toUtc().toIso8601String(),
      'token_type': 'Bearer',
    });

Future<
    ({
      FakeApplicationApi api,
      ApplicationSession session,
      DeviceIdentity identity,
      ApplicationIdentity application,
      DateTime now,
    })> harness() async {
  final now = DateTime.utc(2026, 9, 7, 12);
  final identity = await DeviceIdentity.generate();
  final application = ApplicationIdentity(
    applicationId: 'application-1',
    name: 'Zagros',
    status: 'active',
    signingKeyId: 'signing-key-1',
    signingPublicKey: List<int>.filled(32, 2),
    configKeyId: 'config-key-1',
    configPublicKey: List<int>.filled(32, 3),
  );
  final executor = SignedRequestExecutor(
    transport: RejectingTransport(),
    application: application,
    deviceKeyPair: identity.keyPair,
  );
  final api = FakeApplicationApi(
    executor: executor,
    deviceIdentity: identity,
    now: now,
  );
  final store = MemoryTokenStore();
  final session = ApplicationSession(
    api: api,
    deviceId: 'device-1',
    storage: store,
    clock: () => now,
  );
  await session.setTokens(tokens(now));
  return (
    api: api,
    session: session,
    identity: identity,
    application: application,
    now: now,
  );
}

void main() {
  test('acquisition is list-select-start-immediate-consume', () async {
    final h = await harness();
    final scheduler = ManualScheduler();
    final acquired = await ConfigAcquisition(
      api: h.api,
      session: h.session,
      application: h.application,
      deviceKeyPair: h.identity.keyPair,
      envelopeOpener: FakeEnvelopeOpener(),
      scheduler: scheduler,
      clock: () => h.now,
    ).acquire((selectors) => selectors.single);

    expect(h.api.calls, <String>[
      'list:1',
      'start:selector-1',
      'consume:selector-1',
    ]);
    expect(acquired.normalized.protocol, 'vless');
    expect(scheduler.actions, hasLength(1));
    expect(scheduler.actions.single.delay, const Duration(seconds: 80));
    acquired.lifecycle.detach();
    acquired.disposeRuntimeConfig();
  });

  test('grant expiry transparently restarts bounded acquisition', () async {
    final h = await harness();
    h.api.grantExpiresOnFirstConsume = true;
    final acquired = await ConfigAcquisition(
      api: h.api,
      session: h.session,
      application: h.application,
      deviceKeyPair: h.identity.keyPair,
      envelopeOpener: FakeEnvelopeOpener(),
      scheduler: ManualScheduler(),
      clock: () => h.now,
    ).acquire((selectors) => selectors.single);

    expect(h.api.calls, <String>[
      'list:1',
      'start:selector-1',
      'consume:selector-1',
      'list:2',
      'start:selector-2',
      'consume:selector-2',
    ]);
    acquired.lifecycle.detach();
    acquired.disposeRuntimeConfig();
  });

  test('ambiguous transport loss restarts with fresh authority', () async {
    final h = await harness();
    h.api.transportFailsOnFirstConsume = true;
    final acquired = await ConfigAcquisition(
      api: h.api,
      session: h.session,
      application: h.application,
      deviceKeyPair: h.identity.keyPair,
      envelopeOpener: FakeEnvelopeOpener(),
      scheduler: ManualScheduler(),
      clock: () => h.now,
    ).acquire((selectors) => selectors.single);
    expect(h.api.listCount, 2);
    acquired.lifecycle.detach();
    acquired.disposeRuntimeConfig();
  });

  test('authority recovery remains bounded', () async {
    final h = await harness();
    h.api.grantAlwaysExpires = true;
    await expectLater(
      ConfigAcquisition(
        api: h.api,
        session: h.session,
        application: h.application,
        deviceKeyPair: h.identity.keyPair,
        envelopeOpener: FakeEnvelopeOpener(),
        scheduler: ManualScheduler(),
        clock: () => h.now,
      ).acquire((selectors) => selectors.single),
      throwsA(isA<ZagrosApiException>()),
    );
    expect(h.api.listCount, 2);
  });

  test(
    'expired access token refreshes once and restarts acquisition',
    () async {
      final h = await harness();
      h.api.unauthorizedOnFirstList = true;
      final acquired = await ConfigAcquisition(
        api: h.api,
        session: h.session,
        application: h.application,
        deviceKeyPair: h.identity.keyPair,
        envelopeOpener: FakeEnvelopeOpener(),
        scheduler: ManualScheduler(),
        clock: () => h.now,
      ).acquire((selectors) => selectors.single);
      expect(h.api.refreshCount, 1);
      expect(h.api.listCount, 2);
      acquired.lifecycle.detach();
      acquired.disposeRuntimeConfig();
    },
  );

  test('local envelope expiry transparently obtains fresh authority', () async {
    final h = await harness();
    final opener = FakeEnvelopeOpener()..expireFirst = true;
    final acquired = await ConfigAcquisition(
      api: h.api,
      session: h.session,
      application: h.application,
      deviceKeyPair: h.identity.keyPair,
      envelopeOpener: opener,
      scheduler: ManualScheduler(),
      clock: () => h.now,
    ).acquire((selectors) => selectors.single);
    expect(h.api.listCount, 2);
    expect(opener.calls, 2);
    acquired.lifecycle.detach();
    acquired.disposeRuntimeConfig();
  });

  test('lease lifecycle renews proactively and reschedules', () async {
    final h = await harness();
    final scheduler = ManualScheduler();
    final lifecycle = ConnectionLifecycle(
      api: h.api,
      session: h.session,
      initial: h.api.connection(
        'selector-1',
        h.now.add(const Duration(seconds: 120)),
      ),
      scheduler: scheduler,
      clock: () => h.now,
    )..start();
    expect(scheduler.actions.single.delay, const Duration(seconds: 80));
    scheduler.actions.single.fire();
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    expect(h.api.calls, contains('renew:connection-selector-1:true'));
    expect(
      lifecycle.connection.notAfter,
      h.now.add(const Duration(seconds: 240)),
    );
    expect(scheduler.actions.last.delay, const Duration(seconds: 180));
    lifecycle.detach();
  });

  test('renewal retries transient transport failures before expiry', () async {
    final h = await harness();
    h.api.renewalError = const ZagrosTransportException('temporary');
    final scheduler = ManualScheduler();
    final lifecycle = ConnectionLifecycle(
      api: h.api,
      session: h.session,
      initial: h.api.connection(
        'selector-1',
        h.now.add(const Duration(seconds: 120)),
      ),
      scheduler: scheduler,
      clock: () => h.now,
    )..start();
    scheduler.actions.single.fire();
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    expect(scheduler.actions, hasLength(2));
    expect(scheduler.actions.last.delay, const Duration(seconds: 2));
    lifecycle.detach();
  });

  test('renewal does not retry terminal authorization denial', () async {
    final h = await harness();
    h.api.renewalError = ZagrosApiException(
      statusCode: 403,
      code: 'device_revoked',
      message: 'revoked',
    );
    final scheduler = ManualScheduler();
    final lifecycle = ConnectionLifecycle(
      api: h.api,
      session: h.session,
      initial: h.api.connection(
        'selector-1',
        h.now.add(const Duration(seconds: 120)),
      ),
      scheduler: scheduler,
      clock: () => h.now,
    )..start();
    scheduler.actions.single.fire();
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    expect(scheduler.actions, hasLength(1));
    lifecycle.detach();
  });

  test('concurrent access-token refresh is coalesced', () async {
    final h = await harness();
    final nearExpiry = AuthTokens.fromJson(<String, Object?>{
      'access_token': 'old',
      'access_expires_at':
          h.now.add(const Duration(seconds: 5)).toIso8601String(),
      'refresh_token': 'refresh-token-with-sufficient-test-length',
      'refresh_expires_at':
          h.now.add(const Duration(hours: 1)).toIso8601String(),
      'token_type': 'Bearer',
    });
    await h.session.setTokens(nearExpiry);
    final results = await Future.wait(<Future<String>>[
      h.session.accessToken(),
      h.session.accessToken(),
    ]);
    expect(results, <String>['refreshed', 'refreshed']);
    expect(h.api.refreshCount, 1);
  });
}
