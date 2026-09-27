# authgate-client

[![CI](https://github.com/boskodjokic/authgate-python/actions/workflows/ci.yml/badge.svg)](https://github.com/boskodjokic/authgate-python/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/authgate-client)](https://pypi.org/project/authgate-client/)
[![Python](https://img.shields.io/pypi/pyversions/authgate-client)](https://pypi.org/project/authgate-client/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/boskodjokic/authgate-python/blob/main/LICENSE)

Verify [AuthGate](https://github.com/boskodjokic/authgate) access tokens in Python. Framework-free,
with one dependency — PyJWT and its `crypto` extra — and an optional FastAPI integration. Installed
as `authgate-client`, imported as `authgate`.

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from authgate import AuthGate, Identity

auth = AuthGate(issuer="https://auth.example.com", audience="https://api.example.com")
app = FastAPI()


@app.get("/materials")
def list_materials(caller: Annotated[Identity, Depends(auth.identity)]):
    return materials.for_tenant(caller.tenant_id)


@app.delete("/materials/{material_id}")
def delete_material(material_id: str, caller: Annotated[Identity, Depends(auth.require("material", "delete"))]):
    materials.delete(material_id, by=caller.account_id)
```

```bash
pip install authgate-client              # the verifier
pip install "authgate-client[fastapi]"   # plus the FastAPI dependencies
```

## You may not need this

AuthGate publishes a standard `/.well-known/openid-configuration` and JWKS, so any JWT library that
can fetch a JWKS already verifies its tokens. This package is a convenience, the Python counterpart
of the server's Spring starter. What it adds is what a hand-written verifier usually gets wrong:

- **The audience is required.** A verifier that skips `aud` accepts every token the issuer ever
  minted, including tokens meant for a different service. There is no default for "any".
- **A typed caller.** The `perms` claim arrives as `Identity.permissions`, and
  `caller.may("material", "update")` applies the server's own rule, superuser included.
- **Key refresh that cannot be turned against the issuer.** Tokens naming an unknown `kid` trigger
  at most one JWKS fetch every 30 seconds, however many arrive.
- **An outage is not a bad token.** If the issuer cannot be reached, the answer is 503, not 401 —
  a 401 tells well-behaved clients to throw their token away and sign the user out.

## Without FastAPI

`verify` is plain synchronous code, so it works in Flask, Django, a worker or a script:

```python
from authgate import AuthGate, InvalidTokenError, IssuerUnavailableError

auth = AuthGate(issuer="https://auth.example.com", audience="https://api.example.com")

try:
    caller = auth.verify(token)
except InvalidTokenError:
    ...  # 401
except IssuerUnavailableError:
    ...  # 503

if not caller.may("material", "update"):
    ...  # 403
```

It is also why the FastAPI dependencies are plain `def`s: FastAPI runs them in its threadpool, so
the occasional key fetch never blocks the event loop. With the keys cached, verifying a token is
normally a signature check and nothing else.

## Testing an app that uses it

Override `auth.identity` to stand in a caller. Every `require()` builds on it, so the permission
checks still run against the identity you supply:

```python
app.dependency_overrides[auth.identity] = lambda: Identity("acct-1", permissions={"material": frozenset({"read"})})
```

The dependencies are for HTTP routes, since they read the `Authorization` header. Use them with
`Depends`, not `Security(..., scopes=...)`: scopes make FastAPI treat each use as a separate
dependency, and the token would be verified once per use instead of once per request.

## What is checked

| Check | Rule |
|---|---|
| Signature | RS256 only. The algorithm is pinned, never read from the token header, which closes `alg: none` and the RSA-key-as-HMAC-secret confusion. It is checked before any key lookup, so such a token is refused as invalid even while the issuer is down |
| Key | the `kid` header must name an RS256 signing key the issuer publishes. If the issuer cannot be reached to look one up, the answer is 503, not 401 |
| Issuer | `iss` must equal the discovery document's `issuer` exactly, and that document must name the issuer you configured |
| Audience | `aud` must contain the audience you configured |
| Lifetime | `exp` and `iat` required, `nbf` honoured if present, with 60 seconds of clock skew allowed (`leeway=`, up to 300). An `iat` further in the future than that is rejected — stricter than Spring, which checks only `exp` and `nbf` |
| Required claims | `exp`, `iat`, `iss`, `aud`, `sub`, `jti` |
| Transport | the issuer must be `https://host[:port][/path]`; plain `http://` is accepted only for `localhost`, `127.0.0.1` and `::1` |

Keys are fetched on first use — constructing an `AuthGate` does no I/O — and cached for five
minutes. A failed refresh keeps serving the cached keys rather than failing every request — until
a refresh succeeds, however long that takes, so a key the issuer withdraws during an outage is
trusted until the verifier can see that it is gone.

## The caller

| `Identity` field | Claim | |
|---|---|---|
| `account_id` | `sub` | AuthGate's account id, not the external provider's subject |
| `tenant_id` | `tenant` | |
| `email` | `email` | for display and audit |
| `superuser` | `superuser` | `True` only for a literal JSON `true` |
| `permissions` | `perms` | `{resource: frozenset(actions)}` |
| `claims` | all of them | the verified payload; not part of equality, so two tokens for one caller compare equal |

## Errors

| Raised | Meaning | FastAPI response |
|---|---|---|
| — | no `Authorization: Bearer` header at all | 401, `WWW-Authenticate: Bearer` |
| `InvalidTokenError` | the token is not acceptable here | 401, `WWW-Authenticate: Bearer error="invalid_token"` |
| `IssuerUnavailableError` | the issuer's keys cannot be fetched | 503, with a fixed message; the detail is logged |
| `ConfigurationError` | the verifier is set up wrong, or the issuer's discovery document contradicts it | raised at construction; 500 if discovered later |
| — | a missing permission in `require()` | 403, `WWW-Authenticate: Bearer error="insufficient_scope"` |

All three exceptions derive from `AuthGateError`.

The public API is what `authgate` exports — `AuthGate`, `Identity` and the errors above. The
submodules are implementation, and may change between releases.

## Revocation

AuthGate revokes an access token by adding its `jti` to a denylist on the server. A verifier
working from the published keys cannot see that list, so a token that was already issued stays
valid here until it expires. The server's short access-token lifetime — 15 minutes by default — is
what bounds that window, and revocation is enforced where a new token would be issued. Every
JWT-issuing provider behaves this way.

## Development

```bash
pip install -e ".[dev]" "ruff==0.16.9"   # the ruff CI pins
pytest
ruff check . && ruff format --check .
```

The tests run against an in-process fake issuer: a real RSA key, a real JWKS served over real HTTP
on `127.0.0.1`, and tokens carrying exactly the claims the server issues. That is what makes each
attack — `alg: none`, HMAC confusion, a foreign key reusing a known `kid`, a tampered payload — a
short test with no external network.

## License

MIT — see [LICENSE](https://github.com/boskodjokic/authgate-python/blob/main/LICENSE).
