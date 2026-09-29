# Application API mapping

The panel OpenAPI schemas and `/api/application/v1` implementation are authoritative. `ApplicationApi` maps them as follows.

| Method | Route | SDK method | Retry class |
|---|---|---|---|
| POST | `/devices/enroll` | `enroll` | never blind-retry |
| POST | `/auth/login` | `login` | never blind-retry |
| POST | `/auth/refresh` | `refresh` | coalesced per session |
| POST | `/auth/logout` | `logout` | no blind retry; local tokens always cleared |
| GET | `/user/profile` | `profile` | safe read |
| GET | `/devices` | `devices` | safe read |
| POST | `/devices/{id}/revoke` | `revokeDevice` | never blind-retry |
| GET | `/configs` | `listConfigs` | safe only as part of acquisition semantics |
| POST | `/connections/start` | `startConnection` | retry only by restarting fresh-authority acquisition |
| GET | `/configs/{id}` | `consumeConfig` | never replay blindly; restart fresh-authority acquisition |
| POST | `/connections/{id}/stop` | `stopConnection` | never blind-retry |
| GET | `/connections/status` | `connectionStatus` | safe read; `renew=true` is idempotent |
| GET | `/usage/summary` | `usageSummary` | safe read |
| GET | `/usage/history` | `usageHistory` | safe cursor page |

Every request, including enrollment, is signed with an independent installation X25519 private key and the configured Application public key. Username/password alone never produce an authenticated config request. Body hashes cover the exact UTF-8 bytes sent by `HttpApiTransport`.

`AuthenticatedApplicationClient` retries only read operations after one forced token refresh. Mutations remain explicit. `ConfigAcquisition` owns the special bounded recovery rules for start/consume ambiguity.
