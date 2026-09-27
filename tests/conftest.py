import pytest

from authgate import AuthGate
from tests.fake_issuer import FakeIssuer


@pytest.fixture
def issuer():
    fake = FakeIssuer()
    yield fake
    fake.close()


@pytest.fixture
def auth(issuer):
    return AuthGate(issuer=issuer.issuer, audience=issuer.audience)
