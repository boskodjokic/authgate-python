"""FastAPI integration — the only module in the package that imports a web framework.

Reached through `AuthGate.identity` and `AuthGate.require`; there is nothing here to import directly.

No `from __future__ import annotations` in this module: FastAPI reads the dependency signatures
below at runtime, and `require`'s annotation refers to a closure variable that string annotations
could not resolve.
"""

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .errors import InvalidTokenError, IssuerUnavailableError
from .identity import Identity

if TYPE_CHECKING:
    from .verifier import AuthGate

log = logging.getLogger("authgate")

# auto_error=False so a missing token gets the same 401 and WWW-Authenticate header as a bad one,
# rather than FastAPI's own response. The scheme still shows up in the OpenAPI document.
_bearer = HTTPBearer(auto_error=False)


def identity_dependency(auth: "AuthGate") -> Callable[..., Identity]:
    # A plain `def`, not `async def`: FastAPI runs it in its threadpool, so the rare key fetch
    # never blocks the event loop.
    def identity(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]) -> Identity:
        if credentials is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "missing bearer token", headers={"WWW-Authenticate": "Bearer"}
            )
        try:
            # Stripped because FastAPI versions disagree on whether they do it: RFC 6750 allows more
            # than one space after "Bearer", and only newer releases trim it off.
            return auth.verify(credentials.credentials.strip())
        except InvalidTokenError as exc:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, str(exc), headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
            ) from exc
        except IssuerUnavailableError as exc:
            # The detail — internal host names, network errors, the caller's kid — is for the log, not
            # for an unauthenticated caller. Truncated, because part of it is caller-supplied.
            log.warning("Answering 503, the token issuer is unavailable: %.500s", exc)
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "the token issuer is unavailable") from exc

    return identity


def require_dependency(auth: "AuthGate", resource: str, action: str) -> Callable[..., Identity]:
    identity = auth.identity

    def require(caller: Annotated[Identity, Depends(identity)]) -> Identity:
        if not caller.may(resource, action):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"missing permission: {action} on {resource}",
                # RFC 6750 §3.1, and what Spring's resource server answers the same denial with.
                headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
            )
        return caller

    return require
