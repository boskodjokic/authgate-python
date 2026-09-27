import base64
import json
import time

import jwt
import pytest

from authgate import AuthGate, ConfigurationError, InvalidTokenError, IssuerUnavailableError
from tests.fake_issuer import OMIT, SigningKey, b64url, encode_segment

# -- configuration ----------------------------------------------------------------------------


@pytest.mark.parametrize("issuer", ["", "   ", None, 5])
def test_issuer_is_required(issuer):
    with pytest.raises(ConfigurationError, match="issuer"):
        AuthGate(issuer=issuer, audience="https://api.example.com")


@pytest.mark.parametrize("audience", ["", "   ", None, ["https://a.example.com", "https://b.example.com"]])
def test_audience_is_required_as_one_string(audience):
    with pytest.raises(ConfigurationError, match="audience"):
        AuthGate(issuer="https://auth.example.com", audience=audience)


@pytest.mark.parametrize(
    "issuer", ["http://auth.example.com", "http://localhost.evil.com", "ftp://auth.example.com", "auth.example.com"]
)
def test_issuer_must_be_https(issuer):
    with pytest.raises(ConfigurationError, match="https"):
        AuthGate(issuer=issuer, audience="https://api.example.com")


@pytest.mark.parametrize(
    "issuer",
    [
        "https://",
        "https:///path",
        "https://auth.example.com?tenant=1",
        "https://auth.example.com#section",
        "https://user@auth.example.com",
        "http://evil.example.com@localhost:8080",
        "https://auth.example.com:port",
        "https://auth .example.com",
        "https://auth.example.com\x00",
        "http://[::1",
    ],
)
def test_issuer_must_be_a_plain_url(issuer):
    with pytest.raises(ConfigurationError):
        AuthGate(issuer=issuer, audience="https://api.example.com")


@pytest.mark.parametrize("issuer", ["http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"])
def test_plain_http_is_allowed_for_localhost(issuer):
    assert AuthGate(issuer=issuer, audience="http://localhost:8080").issuer == issuer


def test_trailing_slash_is_dropped():
    assert AuthGate(issuer="https://auth.example.com/", audience="x").issuer == "https://auth.example.com"


@pytest.mark.parametrize("leeway", [float("nan"), float("inf"), -1, 301, "60", None, True])
def test_leeway_must_be_a_sane_number_of_seconds(leeway):
    with pytest.raises(ConfigurationError, match="leeway"):
        AuthGate(issuer="https://auth.example.com", audience="x", leeway=leeway)


def test_issuer_and_audience_are_read_only(auth):
    with pytest.raises(AttributeError):
        auth.audience = "https://other-api.example.com"
    with pytest.raises(AttributeError):
        auth.issuer = "https://evil.example.com"


def test_construction_does_no_io(issuer):
    AuthGate(issuer=issuer.issuer, audience=issuer.audience)

    assert issuer.requests == []


# -- accepted tokens --------------------------------------------------------------------------


def test_a_valid_token_yields_its_identity(issuer, auth):
    token = issuer.mint(sub="acct-1", tenant="tenant-1", perms={"material": ["read"]})

    identity = auth.verify(token)

    assert identity.account_id == "acct-1"
    assert identity.tenant_id == "tenant-1"
    assert identity.email == "ada@example.com"
    assert identity.may("material", "read")
    assert not identity.may("material", "update")


def test_clock_skew_within_the_leeway_is_tolerated(issuer, auth):
    now = int(time.time())

    assert auth.verify(issuer.mint(iat=now - 960, exp=now - 30))


def test_a_custom_leeway_is_honoured(issuer):
    now = int(time.time())
    strict = AuthGate(issuer=issuer.issuer, audience=issuer.audience, leeway=0)

    with pytest.raises(InvalidTokenError, match="Signature has expired"):
        strict.verify(issuer.mint(iat=now - 960, exp=now - 30))


def test_an_audience_list_naming_this_service_is_accepted(issuer, auth):
    assert auth.verify(issuer.mint(aud=["https://other-api.example.com", issuer.audience]))


def test_iss_must_match_the_discovery_document_exactly(issuer, auth):
    issuer.discovery_issuer = issuer.issuer + "/"

    assert auth.verify(issuer.mint(iss=issuer.issuer + "/"))
    with pytest.raises(InvalidTokenError, match="Invalid issuer"):
        auth.verify(issuer.mint())


# -- rejected tokens --------------------------------------------------------------------------


def expired(issuer):
    now = int(time.time())
    return issuer.mint(iat=now - 1_000, exp=now - 120)


def tampered(issuer):
    header, _, signature = issuer.mint().split(".")
    payload = base64.urlsafe_b64encode(json.dumps(issuer.claims(superuser=True)).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.{signature}"


def with_header(header):
    """A real token with its header swapped — for headers PyJWT refuses to encode."""

    def make(issuer):
        _, payload, signature = issuer.mint().split(".")
        return f"{encode_segment(header)}.{payload}.{signature}"

    return make


def deeply_nested_header(issuer):
    # Deep enough to overflow every supported interpreter's JSON parser: 3.13's copes with 5,000.
    header = b'{"alg":"RS256","kid":"x","a":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    return f"{b64url(header)}.e30.c2ln"


def in_the_future(**claims):
    now = int(time.time())
    return lambda issuer: issuer.mint(**{name: now + offset for name, offset in claims.items()})


REJECTED = {
    "expired": (expired, "Signature has expired"),
    "not yet valid": (in_the_future(nbf=600), "not yet valid"),
    "issued in the future": (in_the_future(iat=600, exp=1_500), "not yet valid"),
    "wrong audience": (lambda i: i.mint(aud="https://other-api.example.com"), "not intended for this service"),
    "audience list without us": (lambda i: i.mint(aud=["https://a.example.com"]), "not intended for this service"),
    "wrong issuer": (lambda i: i.mint(iss="https://evil.example.com"), "Invalid issuer"),
    "no jti": (lambda i: i.mint(jti=OMIT), 'missing the "jti" claim'),
    "no sub": (lambda i: i.mint(sub=OMIT), 'missing the "sub" claim'),
    "no exp": (lambda i: i.mint(exp=OMIT), 'missing the "exp" claim'),
    "unknown kid": (lambda i: i.mint(header={"kid": "not-ours"}), "unknown key"),
    "no kid": (lambda i: i.mint(header={}), "no kid"),
    "kid not a string": (with_header({"alg": "RS256", "kid": 5}), "malformed"),
    "unsupported crit": (lambda i: i.mint(header={"kid": i.key.kid, "crit": ["urn:example:x"]}), "malformed"),
    "alg none": (lambda i: i.unsigned(), "alg 'none' is not allowed"),
    "hmac confusion": (lambda i: i.hmac_with_public_key(), "alg 'HS256' is not allowed"),
    "foreign key, our kid": (
        lambda i: i.mint(key=SigningKey(), header={"kid": i.key.kid}),
        "Signature verification failed",
    ),
    "tampered payload": (tampered, "Signature verification failed"),
    "deeply nested header": (deeply_nested_header, "malformed"),
    "not a jwt": (lambda i: "hello", "malformed"),
    "not a string": (lambda i: None, "malformed"),
}


@pytest.mark.parametrize("make, reason", REJECTED.values(), ids=REJECTED.keys())
def test_rejects(issuer, auth, make, reason):
    token = make(issuer)

    with pytest.raises(InvalidTokenError, match=reason):
        auth.verify(token)


def test_a_token_that_can_never_verify_is_invalid_even_while_the_issuer_is_down(issuer, auth):
    issuer.down = True

    with pytest.raises(InvalidTokenError, match="alg"):
        auth.verify(issuer.unsigned())

    assert issuer.requests == []  # refused without asking the issuer anything


def test_an_unreachable_issuer_is_not_reported_as_a_bad_token(issuer, auth):
    issuer.down = True

    with pytest.raises(IssuerUnavailableError):
        auth.verify(issuer.mint())


def test_a_parser_recursion_error_while_decoding_is_an_invalid_token(issuer, auth, monkeypatch):
    # The same PyJWT gap one step later: a header shallow enough to parse once can still overflow
    # when jwt.decode parses it again, a couple of frames deeper.
    def overflow(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(jwt, "decode", overflow)

    with pytest.raises(InvalidTokenError):
        auth.verify(issuer.mint())


def test_never_verifies_without_the_discovered_issuer(issuer, auth, monkeypatch):
    # PyJWT skips the iss check when handed no issuer, so a key without one must fail closed.
    monkeypatch.setattr(auth._keys, "get", lambda kid: issuer.key.private.public_key())

    with pytest.raises(IssuerUnavailableError):
        auth.verify(issuer.mint())
