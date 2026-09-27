"""An in-process stand-in for an AuthGate server: real RSA keys, a real JWKS over real HTTP, and
real signed tokens.

The Python counterpart of `FakeIdp` in the server's test suite. Tokens carry exactly the claims
`AccessTokenIssuer` puts in them and a `kid` derived the way `SigningKeys` derives it, so passing
here means passing against the real contract — which the local interop check then confirms.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

OMIT = object()
"""Pass as a claim override to leave that claim out of the token."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def encode_segment(value: dict[str, Any]) -> str:
    return b64url(json.dumps(value, separators=(",", ":")).encode())


def thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint of an RSA JWK — how SigningKeys derives its `kid`."""
    canonical = json.dumps({name: jwk[name] for name in ("e", "kty", "n")}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode()).digest())


class SigningKey:
    """An RSA key pair whose `kid` is its RFC 7638 thumbprint, as SigningKeys computes it."""

    def __init__(self) -> None:
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = RSAAlgorithm.to_jwk(self.private.public_key(), as_dict=True)
        self.kid = thumbprint(jwk)
        # Exactly the members Nimbus serves for the server's key. PyJWT's to_jwk also adds key_ops,
        # which AuthGate never sends.
        self.public_jwk = {
            "kty": jwk["kty"],
            "n": jwk["n"],
            "e": jwk["e"],
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
        }

    def public_pem(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


class FakeIssuer:
    """Serves discovery and JWKS on 127.0.0.1, and mints tokens signed by the published key."""

    def __init__(self, audience: str = "https://api.example.com") -> None:
        self.audience = audience
        self.key = SigningKey()
        self.published = [self.key]
        self.requests: list[str] = []
        self.down = False
        self.discovery_issuer: str | None = None
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.issuer = f"http://127.0.0.1:{self._server.server_port}"
        # A short poll interval because shutdown() waits for the loop to notice; at the default
        # 0.5 s every test using this fixture would pay half a second to tear it down.
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def rotate(self) -> SigningKey:
        """Publish a new key alongside the old one and sign with it from now on."""
        self.key = SigningKey()
        self.published.append(self.key)
        return self.key

    def claims(self, **overrides: Any) -> dict[str, Any]:
        """AccessTokenIssuer's claim set, with overrides applied (OMIT removes a claim)."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": str(uuid.uuid4()),
            "aud": self.audience,
            "iat": now,
            "exp": now + 900,
            "jti": str(uuid.uuid4()),
            "tenant": str(uuid.uuid4()),
            "email": "ada@example.com",
            "perms": {"material": ["read", "update"]},
            "superuser": False,
        }
        for name, value in overrides.items():
            if value is OMIT:
                claims.pop(name, None)
            else:
                claims[name] = value
        return claims

    def mint(self, *, key: SigningKey | None = None, header: dict[str, Any] | None = None, **overrides: Any) -> str:
        """A token signed like AuthGate signs one.

        The header is `{"kid", "alg"}` and nothing else, as Nimbus writes it — PyJWT's default `typ`
        is suppressed. `header` replaces the `{"kid": ...}` part; PyJWT still sets `alg`, and an `alg`
        inside `header` changes the signing algorithm.
        """
        key = key or self.key
        return jwt.encode(
            self.claims(**overrides),
            key.private,
            algorithm="RS256",
            headers={"typ": None, **({"kid": key.kid} if header is None else header)},
        )

    def unsigned(self, **overrides: Any) -> str:
        """An `alg: none` token naming our kid — accepted by a verifier that trusts the header."""
        header = {"alg": "none", "typ": "JWT", "kid": self.key.kid}
        return f"{encode_segment(header)}.{encode_segment(self.claims(**overrides))}."

    def hmac_with_public_key(self, **overrides: Any) -> str:
        """HS256 with the published public key as the secret — the classic algorithm confusion."""
        header = {"alg": "HS256", "typ": "JWT", "kid": self.key.kid}
        signing_input = f"{encode_segment(header)}.{encode_segment(self.claims(**overrides))}"
        signature = hmac.new(self.key.public_pem(), signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{b64url(signature)}"

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        issuer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 — the stdlib's name
                issuer.requests.append(self.path)
                if issuer.down:
                    self.send_error(503)
                    return
                if self.path == "/.well-known/openid-configuration":
                    body = {
                        "issuer": issuer.discovery_issuer or issuer.issuer,
                        "jwks_uri": f"{issuer.issuer}/.well-known/jwks.json",
                    }
                elif self.path == "/.well-known/jwks.json":
                    body = {"keys": [key.public_jwk for key in issuer.published]}
                else:
                    self.send_error(404)
                    return
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:  # silence per-request stderr lines
                pass

        return Handler
