"""Verifies AuthGate access tokens."""

from __future__ import annotations

from urllib.parse import urlsplit

import jwt

from .errors import ConfigurationError, InvalidTokenError, IssuerUnavailableError
from .identity import Identity
from .keys import KeyCache

# Pinned, never read from the token header — that is what closes `alg: none` and the HMAC
# confusion attack, where an RSA public key is presented as an HMAC secret.
_ALGORITHMS = ["RS256"]
_REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub", "jti"]
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
# Clock skew beyond a few minutes is a broken clock, not skew — and against tokens that live for
# fifteen, a larger allowance would quietly extend every one of them.
_MAX_LEEWAY_SECONDS = 300
# PyJWT before 2.15 lets a deeply nested header escape json.loads as a RecursionError. Any caller can
# send one, so it has to be a 401 rather than a 500 whatever PyJWT version is installed.
_PARSE_ERRORS = (jwt.PyJWTError, RecursionError)


class AuthGate:
    """Verifies tokens issued by one AuthGate server for one audience.

    Construction does no I/O. The issuer's discovery document and keys are fetched on first use and
    cached, so verifying a token is normally a signature check and nothing else.
    """

    def __init__(self, issuer: str, audience: str, *, leeway: float = 60) -> None:
        if not isinstance(issuer, str) or not issuer.strip():
            raise ConfigurationError("issuer must be set")
        if not isinstance(audience, str) or not audience.strip():
            raise ConfigurationError(
                "audience must be set, as one string — without it this service would accept any token the issuer "
                "ever minted, including tokens meant for other services"
            )
        issuer = issuer.strip().rstrip("/")
        audience = audience.strip()
        try:
            url = urlsplit(issuer)
            _ = url.port  # raises ValueError for a port that is not a number in range
        except ValueError as exc:
            raise ConfigurationError(f"issuer is not a valid URL: {issuer!r}") from exc
        # Keys fetched over plain HTTP can be swapped in transit. Localhost is exempt because the
        # server's own development issuer is http://localhost:8080.
        if url.scheme != "https" and not (url.scheme == "http" and url.hostname in _LOCAL_HOSTS):
            raise ConfigurationError(f"issuer must be an https URL (plain http only for localhost), got {issuer!r}")
        # An OIDC issuer is scheme://host[:port][/path]. Anything more would be spliced into the
        # discovery URL, and fail as a permanent outage rather than here, at startup.
        if (
            not url.hostname
            or "@" in url.netloc
            or "?" in issuer
            or "#" in issuer
            or any(c.isspace() or not c.isprintable() for c in issuer)
        ):
            raise ConfigurationError(f"issuer must be scheme://host[:port][/path], got {issuer!r}")
        # NaN or infinity would switch expiry checking off entirely; a string would fail every request.
        if isinstance(leeway, bool) or not isinstance(leeway, (int, float)) or not 0 <= leeway <= _MAX_LEEWAY_SECONDS:
            raise ConfigurationError(f"leeway must be between 0 and {_MAX_LEEWAY_SECONDS} seconds, got {leeway!r}")

        self.issuer = issuer
        self.audience = audience
        self._leeway = leeway
        self._keys = KeyCache(issuer)

    def verify(self, token: str) -> Identity:
        """Verify `token` and return the caller it describes.

        Raises InvalidTokenError for anything wrong with the token, and IssuerUnavailableError when
        the issuer's keys cannot be fetched — including when the key a token names could not be
        looked up because the issuer is unreachable.
        """
        try:
            header = jwt.get_unverified_header(token)
        except _PARSE_ERRORS as exc:
            raise InvalidTokenError(f"malformed token: {exc}") from exc
        # Checked before any key lookup, so a token that can never verify costs the issuer nothing and
        # is refused as invalid even while the issuer is down. jwt.decode enforces it again.
        if header.get("alg") not in _ALGORITHMS:
            raise InvalidTokenError(f"token alg {header.get('alg')!r} is not allowed, expected RS256")
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise InvalidTokenError("token has no kid header")

        key = self._keys.get(kid)
        if key is None:
            raise InvalidTokenError(f"token is signed with an unknown key {kid!r}")
        issuer = self._keys.issuer
        if issuer is None:  # fail closed: PyJWT skips the iss check entirely when given no issuer
            raise IssuerUnavailableError("the issuer's discovery document has not been read")

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=_ALGORITHMS,
                audience=self.audience,
                issuer=issuer,
                leeway=self._leeway,
                options={"require": _REQUIRED_CLAIMS},
            )
        except jwt.InvalidAudienceError as exc:
            raise InvalidTokenError(f"token is not intended for this service (expected aud {self.audience!r})") from exc
        except _PARSE_ERRORS as exc:
            raise InvalidTokenError(str(exc)) from exc
        return Identity.from_claims(claims)
