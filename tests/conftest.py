import pytest

from tests.fake_issuer import FakeIssuer


@pytest.fixture
def issuer():
    fake = FakeIssuer()
    yield fake
    fake.close()
