"""The caller, as an AuthGate access token describes them."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Identity:
    """A typed view over a verified token, so handlers are not digging through a claim dict.

    Mirrors `Identity` in the Java starter, so a permission check reads the same in both languages.

    `account_id` is AuthGate's account id (the `sub` claim), not the external provider's subject:
    a service never needs to know which identity provider someone signed in through.

    `claims` takes no part in equality or hashing: two tokens for the same caller differ in `jti`,
    `iat` and `exp`, and still describe the same caller.
    """

    account_id: str
    tenant_id: str | None = None
    email: str | None = None
    superuser: bool = False
    permissions: Mapping[str, frozenset[str]] = field(default_factory=dict, hash=False)
    claims: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_claims(cls, claims: Mapping[str, Any]) -> Identity:
        """Build an identity from a payload that has already been verified. `sub` must be present."""
        permissions: dict[str, frozenset[str]] = {}
        perms = claims.get("perms")
        if isinstance(perms, Mapping):
            for resource, actions in perms.items():
                # A malformed entry grants nothing rather than failing the whole request — the Java
                # starter treats one the same way.
                permissions[resource] = frozenset(map(str, actions)) if isinstance(actions, list) else frozenset()
        return cls(
            account_id=str(claims["sub"]),
            tenant_id=claims.get("tenant"),
            email=claims.get("email"),
            # Only a literal JSON true. A string "true" is a malformed token, not a superuser.
            superuser=claims.get("superuser") is True,
            permissions=permissions,
            claims=dict(claims),
        )

    def may(self, resource: str, action: str) -> bool:
        """Whether this caller may take `action` on `resource`. Superusers pass everything."""
        return self.superuser or action in self.permissions.get(resource, frozenset())
