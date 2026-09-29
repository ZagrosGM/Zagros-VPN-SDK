# OpenVPN static-auth behavior

OpenVPN `static` authentication has one shared credential and cannot be mapped to an independent Application device lease. It is therefore ineligible for Application mode.

The panel omits such entries from `GET /api/application/v1/configs`; the SDK does not receive or render a dead-end item that would fail only after the user presses Connect. Official/manual configuration mode may still import a static-auth profile under its own explicit product policy, but it must never be represented as a renewable White-label Application lease.
