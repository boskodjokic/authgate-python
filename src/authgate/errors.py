"""The errors this package defines.

The verifier is framework-free: it raises these, and `authgate.fastapi` maps them to status codes.
"""


class AuthGateError(Exception):
    """Base for every error this package raises."""


class ConfigurationError(AuthGateError):
    """The verifier is set up wrong, or the issuer's discovery document contradicts the setup."""


class InvalidTokenError(AuthGateError):
    """The caller's token is not acceptable here. Maps to 401."""


class IssuerUnavailableError(AuthGateError):
    """The issuer's signing keys could not be fetched. Maps to 503.

    Kept apart from InvalidTokenError on purpose. Reporting an outage as a 401 tells the client its
    token is bad, and a well-behaved client responds by discarding it and signing the user out.
    """
