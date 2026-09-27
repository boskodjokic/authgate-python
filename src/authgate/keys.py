"""Fetches and caches an issuer's signing keys."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

import jwt

from .errors import AuthGateError, ConfigurationError, IssuerUnavailableError

log = logging.getLogger("authgate")

_TIMEOUT_SECONDS = 5


class KeyCache:
    """The issuer's RS256 public keys, indexed by `kid`.

    Discovery is read once; the JWKS is refreshed when it goes stale or when a token names a key we
    have not seen, which is how a key rotation reaches a running verifier.

    Every fetch *attempt*, successful or not, is spaced at least `min_interval` seconds from the
    last. Without that, a stream of tokens with made-up `kid`s would turn each request into a
    request to the issuer. The defaults — 300 s freshness, 30 s between attempts — are the ones
    Nimbus uses, which is what the Java starter verifies with.
    """

    def __init__(
        self,
        issuer: str,
        *,
        ttl: float = 300,
        min_interval: float = 30,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._issuer = issuer
        self._ttl = ttl
        self._min_interval = min_interval
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, Any] | None = None
        self._fetched_at = 0.0
        self._attempted_at: float | None = None
        self._failure: AuthGateError | None = None
        self._refresh_failed = False
        self._jwks_uri: str | None = None
        self.issuer: str | None = None
        """The `iss` value tokens must carry, exactly as the discovery document states it."""

    def get(self, kid: str) -> Any | None:
        """The key for `kid`, or None if the issuer does not publish one.

        Raises IssuerUnavailableError (or ConfigurationError) while no keys have ever been fetched,
        and IssuerUnavailableError for an unknown `kid` while the last refresh failed — the token
        may be perfectly valid, and a 401 would tell its holder otherwise. Once keys are cached, a
        failed refresh keeps serving them.
        """
        keys = self._keys
        cached = keys is not None and kid in keys
        if cached and not self._stale():
            return keys[kid]

        # Without a usable key, wait for whoever is fetching. With one, never queue behind a slow
        # issuer: the cached key is the best answer until the refresh lands.
        if not self._lock.acquire(blocking=not cached):
            return keys[kid]
        try:
            keys = self._keys
            wanted = keys is None or kid not in keys or self._stale()
            # The rate limit doubles as the re-check: a request that queued on the lock behind one
            # that just fetched finds the attempt too recent and uses what it brought back.
            if wanted and self._may_attempt():
                self._refresh()
            keys, failure, refresh_failed = self._keys, self._failure, self._refresh_failed
        finally:
            self._lock.release()

        if keys is None:
            raise type(failure)(*failure.args) if failure else IssuerUnavailableError("no keys fetched yet")
        if kid not in keys and refresh_failed:
            # Until a refresh succeeds, not every request that names an unknown kid can make its own
            # attempt, so the answer holds for the whole interval, not just the one that tried.
            raise IssuerUnavailableError(f"could not refresh signing keys from {self._issuer} to look for {kid!r}")
        return keys.get(kid)

    def _stale(self) -> bool:
        return self._clock() - self._fetched_at >= self._ttl

    def _may_attempt(self) -> bool:
        return self._attempted_at is None or self._clock() - self._attempted_at >= self._min_interval

    def _refresh(self) -> None:
        """Fetch the JWKS. A failure with keys cached keeps them in use and marks the refresh failed."""
        self._attempted_at = self._clock()
        try:
            if self._jwks_uri is None:
                self._discover()
            keys = _usable_keys(_fetch_json(self._jwks_uri))
        except ConfigurationError as exc:
            # Stored as a fresh instance so the cache does not keep the traceback's frames alive.
            self._failure = ConfigurationError(*exc.args)
            raise
        except Exception as exc:  # whatever went wrong fetching or parsing, the issuer is unavailable to us
            if self._keys is None:
                self._failure = IssuerUnavailableError(f"could not fetch signing keys from {self._issuer}: {exc}")
                raise IssuerUnavailableError(*self._failure.args) from exc
            log.warning("Could not refresh signing keys from %s, keeping cached keys: %r", self._issuer, exc)
            self._refresh_failed = True
            return

        self._keys = keys
        self._fetched_at = self._attempted_at
        self._failure = None
        self._refresh_failed = False

    def _discover(self) -> None:
        url = f"{self._issuer}/.well-known/openid-configuration"
        document = _fetch_json(url)
        stated = document.get("issuer") if isinstance(document, dict) else None
        # A redirect or a misconfigured proxy must not be able to point us at another issuer's keys.
        if not isinstance(stated, str) or stated.rstrip("/") != self._issuer:
            raise ConfigurationError(f"{url} names issuer {stated!r}, expected {self._issuer!r}")
        jwks_uri = document.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            raise ConfigurationError(f"{url} has no jwks_uri")
        self._jwks_uri = jwks_uri
        self.issuer = stated


def _usable_keys(document: Any) -> dict[str, Any]:
    """The RS256 signing keys in a JWKS, by `kid`.

    Anything else is dropped here rather than failing later: an EC key under a `kid` a token names
    would otherwise reach the RS256 verifier and fail as a 500 rather than a 401. If a `kid`
    repeats, the first entry wins, so an unusable duplicate cannot displace a good key.
    """
    keys: dict[str, Any] = {}
    for key in jwt.PyJWKSet.from_dict(document).keys:
        if (
            isinstance(key.key_id, str)
            and key.key_type == "RSA"
            and key.algorithm_name == "RS256"
            and key.public_key_use in (None, "sig")
        ):
            keys.setdefault(key.key_id, key.key)
    if not keys:
        # Treated like any other failed fetch: an issuer publishing nothing usable is broken, and
        # adopting an empty set would reject every token.
        raise ValueError("the JWKS has no RS256 signing key")
    return keys


def _fetch_json(url: str) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        exc.close()  # an error status arrives as an exception that still holds the open response
        raise
