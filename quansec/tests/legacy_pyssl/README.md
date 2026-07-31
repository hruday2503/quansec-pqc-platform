# Quarantined: tests for the Python-`ssl` TLS generation

These five test files and the conftest they depend on target an API that no
longer exists. They import `protocols.tls.adapter`, `protocols.tls.hybrid` and
`protocols.tls.tls13` — the Python-`ssl` client/server generation that was
replaced by the NGINX + OpenSSL 3.5.7 data plane, and they exercise endpoints
(`POST /api/tls/test-connection`, `POST /api/tls/hybrid/verify`) that were
removed with it.

They are kept rather than deleted because their *assertions* are still worth
porting: payload redaction, group-source honesty, and the rule that a group
must never be reported unless it was observed. `legacy/tls13/` still holds the
code they test.

They are NOT collected by pytest (testpaths = tests, and this directory has no
`__init__.py` or conftest wiring). Porting them to the NGINX surface is
outstanding work.
