import dataclasses

import pytest

from authgate import Identity

CLAIMS = {
    "sub": "3f1c",
    "tenant": "acme-id",
    "email": "ada@example.com",
    "perms": {"material": ["read", "update"], "season": ["read"]},
    "superuser": False,
    "jti": "j-1",
}


def test_reads_every_field_from_the_claims():
    identity = Identity.from_claims(CLAIMS)

    assert identity.account_id == "3f1c"
    assert identity.tenant_id == "acme-id"
    assert identity.email == "ada@example.com"
    assert identity.superuser is False
    assert identity.permissions == {"material": frozenset({"read", "update"}), "season": frozenset({"read"})}
    assert identity.claims["jti"] == "j-1"


def test_may_checks_resource_and_action_together():
    identity = Identity.from_claims(CLAIMS)

    assert identity.may("material", "update")
    assert not identity.may("material", "delete")
    assert not identity.may("season", "update")
    assert not identity.may("account", "read")


def test_superuser_may_do_anything():
    identity = Identity.from_claims({**CLAIMS, "perms": {}, "superuser": True})

    assert identity.may("account", "delete")


@pytest.mark.parametrize("value", ["true", 1, None])
def test_superuser_requires_a_literal_true(value):
    assert Identity.from_claims({**CLAIMS, "superuser": value}).superuser is False


def test_malformed_perms_grant_nothing():
    identity = Identity.from_claims({**CLAIMS, "perms": {"material": "read", "season": ["read"]}})

    assert identity.permissions == {"material": frozenset(), "season": frozenset({"read"})}


def test_missing_optional_claims_default_to_empty():
    identity = Identity.from_claims({"sub": "3f1c"})

    assert identity.tenant_id is None
    assert identity.email is None
    assert identity.superuser is False
    assert identity.permissions == {}


def test_a_perms_claim_that_is_not_a_map_grants_nothing():
    assert Identity.from_claims({**CLAIMS, "perms": ["material:read"]}).permissions == {}


def test_only_the_account_id_may_be_passed_positionally():
    with pytest.raises(TypeError):
        Identity("3f1c", "acme-id")


def test_the_same_caller_from_two_tokens_is_equal_and_hashes_alike():
    first = Identity.from_claims(CLAIMS)
    second = Identity.from_claims({**CLAIMS, "jti": "j-2", "iat": 1, "exp": 2})

    assert first == second
    assert hash(first) == hash(second)


def test_serialises_like_a_plain_dataclass():
    # FastAPI encodes a returned dataclass through dataclasses.asdict, so `return caller` has to work.
    serialised = dataclasses.asdict(Identity.from_claims(CLAIMS))

    assert serialised["permissions"]["material"] == frozenset({"read", "update"})
    assert serialised["claims"]["jti"] == "j-1"
