import logging
import sys
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import authgate
from authgate import AuthGate, Identity


@pytest.fixture
def client(auth):
    app = FastAPI()

    @app.get("/me")
    def me(caller: Annotated[Identity, Depends(auth.identity)]):
        return {"account_id": caller.account_id}

    @app.get("/whoami")
    def whoami(caller: Annotated[Identity, Depends(auth.identity)]):
        return caller

    @app.delete("/materials/1")
    def delete_material(caller: Annotated[Identity, Depends(auth.require("material", "delete"))]):
        return {"deleted_by": caller.account_id}

    @app.put("/materials/1", dependencies=[Depends(auth.require("material", "update"))])
    def update_material(caller: Annotated[Identity, Depends(auth.identity)]):
        return {"updated_by": caller.account_id}

    return TestClient(app)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_a_valid_token_reaches_the_handler(issuer, client):
    response = client.get("/me", headers=bearer(issuer.mint(sub="acct-1")))

    assert response.status_code == 200
    assert response.json() == {"account_id": "acct-1"}


def test_the_caller_can_be_returned_as_is(issuer, client):
    response = client.get("/whoami", headers=bearer(issuer.mint(sub="acct-1", perms={"material": ["read"]})))

    assert response.status_code == 200
    assert response.json()["account_id"] == "acct-1"
    assert response.json()["permissions"] == {"material": ["read"]}


def test_no_token_is_401_with_a_bearer_challenge(client):
    response = client.get("/me")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_non_bearer_scheme_is_treated_as_no_token(client):
    response = client.get("/me", headers={"Authorization": "Basic YWRhOnNlY3JldA=="})

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_bad_token_is_401_invalid_token(issuer, client):
    response = client.get("/me", headers=bearer(issuer.mint(aud="https://other-api.example.com")))

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert "not intended for this service" in response.json()["detail"]


def test_a_missing_permission_is_403(issuer, client):
    response = client.delete("/materials/1", headers=bearer(issuer.mint()))

    assert response.status_code == 403
    assert response.json()["detail"] == "missing permission: delete on material"
    assert response.headers["www-authenticate"] == 'Bearer error="insufficient_scope"'


def test_a_granted_permission_passes_and_yields_the_caller(issuer, client):
    token = issuer.mint(sub="acct-1", perms={"material": ["delete"]})

    response = client.delete("/materials/1", headers=bearer(token))

    assert response.status_code == 200
    assert response.json() == {"deleted_by": "acct-1"}


def test_a_superuser_passes_every_permission(issuer, client):
    response = client.delete("/materials/1", headers=bearer(issuer.mint(perms={}, superuser=True)))

    assert response.status_code == 200


def test_an_unreachable_issuer_is_503_not_401(issuer, client, caplog):
    issuer.down = True

    with caplog.at_level(logging.WARNING, logger="authgate"):
        response = client.get("/me", headers=bearer(issuer.mint()))

    assert response.status_code == 503
    assert response.json() == {"detail": "the token issuer is unavailable"}  # no hosts or errors leaked
    assert issuer.issuer in caplog.text  # the detail goes to the log instead


def test_surrounding_whitespace_in_the_token_is_tolerated(issuer, client):
    response = client.get("/me", headers={"Authorization": f"Bearer  {issuer.mint(sub='acct-1')} "})

    assert response.status_code == 200


def test_overriding_identity_also_drives_require(issuer, auth, client):
    # The pattern for testing an app: stand in a caller, and the permission checks still run on it.
    client.app.dependency_overrides[auth.identity] = lambda: Identity("acct-1", permissions={"material": {"read"}})

    assert client.get("/me").json() == {"account_id": "acct-1"}
    assert client.delete("/materials/1").status_code == 403
    assert issuer.requests == []


def test_verifies_once_per_request_when_require_and_identity_are_combined(issuer, auth, client, monkeypatch):
    calls = []
    verify = auth.verify
    monkeypatch.setattr(auth, "verify", lambda token: calls.append(token) or verify(token))

    response = client.put("/materials/1", headers=bearer(issuer.mint()))

    assert response.status_code == 200
    assert len(calls) == 1


def test_the_bearer_scheme_is_in_the_openapi_document(client):
    document = client.get("/openapi.json").json()

    assert document["components"]["securitySchemes"] == {"HTTPBearer": {"type": "http", "scheme": "bearer"}}
    # A route guarded only by require() still shows as protected.
    assert document["paths"]["/materials/1"]["delete"]["security"] == [{"HTTPBearer": []}]


def test_without_fastapi_installed_the_error_names_the_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "fastapi", None)
    monkeypatch.delitem(sys.modules, "authgate.fastapi", raising=False)
    monkeypatch.delattr(authgate, "fastapi", raising=False)
    auth = AuthGate(issuer="https://auth.example.com", audience="https://api.example.com")

    with pytest.raises(ModuleNotFoundError, match=r"authgate-client\[fastapi\]"):
        _ = auth.identity


def test_a_broken_fastapi_install_is_not_disguised_as_a_missing_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "fastapi.security", None)
    monkeypatch.delitem(sys.modules, "authgate.fastapi", raising=False)
    monkeypatch.delattr(authgate, "fastapi", raising=False)
    auth = AuthGate(issuer="https://auth.example.com", audience="https://api.example.com")

    with pytest.raises(ModuleNotFoundError) as raised:
        _ = auth.identity

    assert "authgate-client[fastapi]" not in str(raised.value)
