"""RootSentinel staging gateway agent: a standard-library client of the REST gateway.

The server is the only decision maker. This package never imports the backend, never
holds the protected-hash registry, and delivers a file only after the gateway persisted
an ALLOW decision and released the verified bytes.
"""

__version__ = "0.5.0"
