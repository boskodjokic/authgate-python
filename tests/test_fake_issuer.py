"""The harness is only worth trusting if it is itself right, so check it against the contract."""

import json
import urllib.error
import urllib.request

import jwt
import pytest

from tests.fake_issuer import OMIT, thumbprint


def fetch(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.load(response)


def test_thumbprint_matches_the_rfc_7638_worked_example():
    n = (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV"
        "4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c"
        "7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1j"
        "F44-csFCur-kEgU8awapJzKnqDKgw"
    )

    jwk = {"kty": "RSA", "n": n, "e": "AQAB", "alg": "RS256"}

    assert thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_serves_discovery_pointing_at_its_jwks(issuer):
    document = fetch(f"{issuer.issuer}/.well-known/openid-configuration")

    assert document == {"issuer": issuer.issuer, "jwks_uri": f"{issuer.issuer}/.well-known/jwks.json"}


def test_publishes_only_the_public_half_under_its_thumbprint(issuer):
    keys = fetch(f"{issuer.issuer}/.well-known/jwks.json")["keys"]

    assert [key["kid"] for key in keys] == [issuer.key.kid]
    assert keys[0]["kid"] == thumbprint(keys[0])
    assert set(keys[0]) == {"kty", "n", "e", "kid", "use", "alg"}  # what Nimbus serves; no private members


def test_mints_exactly_access_token_issuer_claims(issuer):
    token = issuer.mint()
    claims = jwt.decode(token, issuer.key.public_pem(), algorithms=["RS256"], audience=issuer.audience)

    assert set(claims) == {"iss", "sub", "aud", "iat", "exp", "jti", "tenant", "email", "perms", "superuser"}
    assert jwt.get_unverified_header(token) == {"alg": "RS256", "kid": issuer.key.kid}


def test_overrides_replace_or_remove_claims(issuer):
    claims = issuer.claims(email="grace@example.com", jti=OMIT)

    assert claims["email"] == "grace@example.com"
    assert "jti" not in claims


def test_counts_requests_and_can_go_down(issuer):
    issuer.down = True

    with pytest.raises(urllib.error.HTTPError) as raised:
        fetch(f"{issuer.issuer}/.well-known/jwks.json")

    raised.value.close()
    assert raised.value.code == 503
    assert issuer.requests == ["/.well-known/jwks.json"]
