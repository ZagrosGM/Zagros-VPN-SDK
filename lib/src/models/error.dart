enum ZagrosErrorKind {
  authentication,
  authorization,
  enrollmentRequired,
  activationTicketInvalid,
  replayRejected,
  rateLimited,
  secureTransportRequired,
  selectorExpired,
  selectorConsumed,
  selectorInvalid,
  connectionRequired,
  connectionFailed,
  connectionNotFound,
  protocolUnavailable,
  deviceNotFound,
  applicationNotFound,
  applicationGrantNotFound,
  applicationKeyNotFound,
  validation,
  requestSigning,
  transport,
  malformedResponse,
  envelopeExpired,
  envelopeInvalid,
  unknown,
}

class ZagrosException implements Exception {
  const ZagrosException(this.kind, this.message, {this.cause});

  final ZagrosErrorKind kind;
  final String message;
  final Object? cause;

  /// This is not blanket permission to retry a mutation. It only identifies
  /// failures recoverable by restarting the bounded fresh-authority flow.
  bool get recoverableByFreshAuthority => switch (kind) {
        ZagrosErrorKind.selectorExpired ||
        ZagrosErrorKind.selectorConsumed ||
        ZagrosErrorKind.selectorInvalid ||
        ZagrosErrorKind.connectionRequired ||
        ZagrosErrorKind.transport ||
        ZagrosErrorKind.envelopeExpired =>
          true,
        _ => false,
      };

  @override
  String toString() => 'ZagrosException($kind, $message)';
}

class ZagrosApiException extends ZagrosException {
  ZagrosApiException({
    required this.statusCode,
    required this.code,
    required String message,
    this.retryAfter,
  }) : super(_kindFor(code, statusCode), message);

  final int statusCode;
  final String code;
  final Duration? retryAfter;

  static ZagrosErrorKind _kindFor(String code, int status) => switch (code) {
        'device_enrollment_required' => ZagrosErrorKind.enrollmentRequired,
        'activation_ticket_invalid' => ZagrosErrorKind.activationTicketInvalid,
        'request_replay_rejected' => ZagrosErrorKind.replayRejected,
        'rate_limited' => ZagrosErrorKind.rateLimited,
        'https_required' => ZagrosErrorKind.secureTransportRequired,
        'config_grant_expired' => ZagrosErrorKind.selectorExpired,
        'config_grant_consumed' => ZagrosErrorKind.selectorConsumed,
        'config_grant_invalid' => ZagrosErrorKind.selectorInvalid,
        'connection_required' => ZagrosErrorKind.connectionRequired,
        'connection_failed' => ZagrosErrorKind.connectionFailed,
        'connection_not_found' => ZagrosErrorKind.connectionNotFound,
        'protocol_unavailable' => ZagrosErrorKind.protocolUnavailable,
        'device_not_found' => ZagrosErrorKind.deviceNotFound,
        'application_not_found' => ZagrosErrorKind.applicationNotFound,
        'application_grant_not_found' =>
          ZagrosErrorKind.applicationGrantNotFound,
        'application_key_not_found' => ZagrosErrorKind.applicationKeyNotFound,
        'invalid_usage_range' ||
        'application_request_rejected' =>
          ZagrosErrorKind.validation,
        'authentication_failed' ||
        'invalid_credentials' =>
          ZagrosErrorKind.authentication,
        'application_access_denied' ||
        'application_inactive' ||
        'application_key_revoked' ||
        'application_grant_denied' ||
        'device_limit_reached' ||
        'device_revoked' ||
        'user_disabled' ||
        'user_expired' ||
        'quota_exhausted' =>
          ZagrosErrorKind.authorization,
        _ when status == 401 => ZagrosErrorKind.authentication,
        _ when status == 403 => ZagrosErrorKind.authorization,
        _ => ZagrosErrorKind.unknown,
      };
}

class ZagrosTransportException extends ZagrosException {
  const ZagrosTransportException(String message, {super.cause})
      : super(ZagrosErrorKind.transport, message);
}
