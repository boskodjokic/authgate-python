import http.client
import threading
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm

from authgate import ConfigurationError, IssuerUnavailableError
from authgate import keys as keys_module
from authgate.keys import KeyCache
from tests.fake_issuer import SigningKey

DISCOVERY = "/.well-known/openid-configuration"
JWKS = "/.well-known/jwks.json"


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def cache(issuer, clock):
    return KeyCache(issuer.issuer, ttl=300, min_interval=30, clock=clock)


def ec_entry(kid):
    """A JWKS entry holding an EC key — valid JSON Web Key, useless to an RS256 verifier."""
    jwk = ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key(), as_dict=True)
    return SimpleNamespace(public_jwk={**jwk, "kid": kid, "use": "sig", "alg": "ES256"})


def test_discovers_once_then_serves_from_cache(issuer, cache):
    assert cache.get(issuer.key.kid) is not None
    assert cache.get(issuer.key.kid) is not None

    assert issuer.requests == [DISCOVERY, JWKS]
    assert cache.issuer == issuer.issuer


def test_unknown_kid_returns_none(issuer, cache):
    assert cache.get("not-a-published-kid") is None


def test_unknown_kids_refetch_at_most_once_per_interval(issuer, cache, clock):
    cache.get(issuer.key.kid)
    clock.advance(30)

    for _ in range(50):
        cache.get("made-up")

    assert issuer.requests == [DISCOVERY, JWKS, JWKS]


def test_a_rotated_key_is_picked_up_on_first_sight(issuer, cache, clock):
    cache.get(issuer.key.kid)
    clock.advance(60)
    new = issuer.rotate()

    assert cache.get(new.kid) is not None
    assert issuer.requests == [DISCOVERY, JWKS, JWKS]


def test_a_key_the_issuer_stops_publishing_stops_being_served(issuer, cache, clock):
    old = issuer.key
    cache.get(old.kid)
    issuer.rotate()
    issuer.published.remove(old)
    clock.advance(300)

    assert cache.get(issuer.key.kid) is not None
    assert cache.get(old.kid) is None


def test_stale_keys_are_refreshed(issuer, cache, clock):
    cache.get(issuer.key.kid)
    clock.advance(300)

    cache.get(issuer.key.kid)

    assert issuer.requests == [DISCOVERY, JWKS, JWKS]


def test_only_rs256_signing_keys_are_used(issuer, cache):
    encryption = SigningKey()
    encryption.public_jwk["use"] = "enc"
    anonymous = SigningKey()
    del anonymous.public_jwk["kid"]
    issuer.published += [encryption, anonymous, ec_entry("ec-key"), ec_entry(issuer.key.kid)]

    assert cache.get(encryption.kid) is None
    assert cache.get(anonymous.kid) is None
    assert cache.get("ec-key") is None
    assert isinstance(cache.get(issuer.key.kid), rsa.RSAPublicKey)


def test_the_first_key_under_a_repeated_kid_wins(issuer, cache):
    impostor = SigningKey()
    impostor.public_jwk["kid"] = issuer.key.kid
    issuer.published.append(impostor)

    assert cache.get(issuer.key.kid).public_numbers() == issuer.key.private.public_key().public_numbers()


def test_a_failed_refresh_keeps_serving_cached_keys(issuer, cache, clock):
    cache.get(issuer.key.kid)
    issuer.down = True
    clock.advance(301)

    assert cache.get(issuer.key.kid) is not None
    assert cache.get(issuer.key.kid) is not None
    assert issuer.requests == [DISCOVERY, JWKS, JWKS]  # the second call was rate limited


def _raise(exc):
    def fetch(url):
        raise exc

    return fetch


UNUSABLE_RESPONSES = {
    "null body": lambda url: None,
    "list body": lambda url: [],
    "keys not a list": lambda url: {"keys": "x"},
    "truncated body": _raise(http.client.IncompleteRead(b"")),
}


@pytest.mark.parametrize("fetch", UNUSABLE_RESPONSES.values(), ids=UNUSABLE_RESPONSES.keys())
def test_an_unusable_refresh_response_keeps_serving_cached_keys(issuer, cache, clock, monkeypatch, fetch):
    cache.get(issuer.key.kid)
    monkeypatch.setattr(keys_module, "_fetch_json", fetch)
    clock.advance(300)

    assert cache.get(issuer.key.kid) is not None


def test_a_jwks_with_no_usable_key_is_a_failed_fetch(issuer, cache):
    issuer.key.public_jwk["use"] = "enc"

    with pytest.raises(IssuerUnavailableError, match="no RS256 signing key"):
        cache.get(issuer.key.kid)


def test_an_unknown_kid_during_an_outage_is_unavailable_not_invalid(issuer, cache, clock):
    cache.get(issuer.key.kid)
    issuer.down = True
    clock.advance(30)

    with pytest.raises(IssuerUnavailableError):
        cache.get("rotated-while-down")
    with pytest.raises(IssuerUnavailableError):  # and for every request until a refresh succeeds
        cache.get("rotated-while-down")


def test_a_cached_key_is_served_without_waiting_for_a_slow_refresh(issuer, cache, clock, monkeypatch):
    cache.get(issuer.key.kid)
    clock.advance(300)
    fetching, release = threading.Event(), threading.Event()
    fetch = keys_module._fetch_json

    def slow_fetch(url):
        fetching.set()
        release.wait(5)
        return fetch(url)

    monkeypatch.setattr(keys_module, "_fetch_json", slow_fetch)
    refresher = threading.Thread(target=cache.get, args=(issuer.key.kid,))
    refresher.start()
    assert fetching.wait(5)

    started = time.monotonic()
    assert cache.get(issuer.key.kid) is not None
    assert time.monotonic() - started < 1

    release.set()
    refresher.join(5)


def test_an_outage_before_the_first_fetch_is_unavailable_not_invalid(issuer, cache):
    issuer.down = True

    with pytest.raises(IssuerUnavailableError):
        cache.get(issuer.key.kid)
    with pytest.raises(IssuerUnavailableError):
        cache.get(issuer.key.kid)

    assert issuer.requests == [DISCOVERY]  # the second call was rate limited, not re-sent


def test_recovers_once_the_issuer_is_back(issuer, cache, clock):
    issuer.down = True
    with pytest.raises(IssuerUnavailableError):
        cache.get(issuer.key.kid)

    issuer.down = False
    clock.advance(30)

    assert cache.get(issuer.key.kid) is not None


def test_discovery_naming_another_issuer_is_a_configuration_error(issuer, cache):
    issuer.discovery_issuer = "https://someone-else.example.com"

    with pytest.raises(ConfigurationError, match="someone-else"):
        cache.get(issuer.key.kid)
    with pytest.raises(ConfigurationError):
        cache.get(issuer.key.kid)

    assert issuer.requests == [DISCOVERY]


def test_keeps_the_discovery_issuer_string_verbatim(issuer, cache):
    issuer.discovery_issuer = issuer.issuer + "/"

    cache.get(issuer.key.kid)

    assert cache.issuer == issuer.issuer + "/"
