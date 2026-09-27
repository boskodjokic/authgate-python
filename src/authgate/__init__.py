"""authgate — verify AuthGate access tokens.

from authgate import AuthGate

auth = AuthGate(issuer="https://auth.example.com", audience="https://api.example.com")
caller = auth.verify(token)
caller.may("material", "update")
"""

from .errors import AuthGateError, ConfigurationError, InvalidTokenError, IssuerUnavailableError
from .identity import Identity

__version__ = "0.1.0"

__all__ = [
    "AuthGateError",
    "ConfigurationError",
    "Identity",
    "InvalidTokenError",
    "IssuerUnavailableError",
    "__version__",
]
