# Changelog

## 0.1.0

First release.

**Added**

- `AuthGate(issuer, audience).verify(token)` — verifies an AuthGate access token and returns the
  caller as a typed `Identity`. RS256 pinned; `iss`, `aud`, `exp` and `iat` checked; `sub` and
  `jti` required; `nbf` honoured; `leeway=` clock skew, 60 s by default and at most 300. Keys come
  from the issuer's discovery document and JWKS, are cached for five minutes, and are refetched on
  an unknown `kid` at most once every 30 seconds.
- `Identity` — `account_id`, `tenant_id`, `email`, `superuser`, `permissions`, the verified
  `claims`, and `may(resource, action)` with the server's superuser rule.
- FastAPI integration behind the `fastapi` extra: `Depends(auth.identity)` and
  `Depends(auth.require(resource, action))`, with 401 / 403 / 503 responses.
- `InvalidTokenError`, `IssuerUnavailableError` and `ConfigurationError`, all derived from
  `AuthGateError`.
