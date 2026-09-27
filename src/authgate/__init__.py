"""authgate — verify AuthGate access tokens.

from authgate import AuthGate

auth = AuthGate(issuer="https://auth.example.com", audience="https://api.example.com")
caller = auth.verify(token)
caller.may("material", "update")
"""

__version__ = "0.1.0"
