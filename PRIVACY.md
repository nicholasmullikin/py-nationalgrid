# Privacy hardening fork

Based on upstream v0.6.6, commit 554e4b93ec07a87caa2de4487d43d6705081490a.

This fork omits request URLs, authentication redirect locations, backend error
payloads and raw exception details from logging, including debug logging.
Configuration repr excludes credentials, subscription keys and custom headers.
Structured exception strings show categories, HTTP status and retry counts;
query, URL, variables, response and original exception attributes remain available
for callers that need them, and must not be serialized or logged publicly.
GraphQL response errors raise a fixed public message instead of copying backend payloads.

Public API methods, verified TLS, PKCE, token refresh and retry behavior are unchanged.
OAuth requests use HTTPX with TLS verification and scoped cookie transfer back
to the caller's aiohttp session. Cookie domain, path and Secure attributes are
preserved across redirects. Transport errors omit private URLs and nested errors.
HTTPX/httpcore URL and header logging is suppressed only in the OAuth request
context; unrelated integrations retain their logging. API requests remain on aiohttp. A live login confirmed two active billing accounts.
The consumer OAuth client/policy and form request format now match the public
myaccount.nationalgrid.com portal observed on 2026-10-11. The old UWP policy
returned a B2C exception before credential validation. Requests use the form
tenant path on the verified issuer host. The business portal policy is preserved.
Unsigned access-token decoding only extracts a subject from a token received over
verified TLS; it does not authorize a request. ID-token verification remains enabled.

Tests: run `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin
-p pytest_cov.plugin`. The privacy tests exercise redirect codes, backend errors,
configuration repr and error summaries with synthetic sensitive values.

Build with `SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PY_NATIONALGRID=0.6.6.post5 python
-m build --wheel`. The GitHub release wheel is pinned by URL and SHA-256 in the
Home Assistant integration fork. Updates require a new reviewed release and hash.
