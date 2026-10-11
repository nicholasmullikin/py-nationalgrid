"""Match the consumer portal's observed October 2026 OAuth form requests."""

import logging
from unittest.mock import AsyncMock, patch

import aiohttp
import httpx
import pytest
from yarl import URL

from py_nationalgrid.auth import NationalGridAuth
from py_nationalgrid.exceptions import CannotConnectError
from py_nationalgrid.oidchelper import _confirm_signin, _fetch, _form_endpoint, _post_credentials

ISSUER = "https://login.nationalgrid.com/tenant-id/v2.0/"
POLICY = NationalGridAuth.POLICY
SETTINGS = {
    "hosts": {"tenant": f"/login.nationalgridus.com/{POLICY}"},
    "csrf": "synthetic-csrf",
    "transId": "synthetic-transaction",
}


@pytest.mark.asyncio
async def test_consumer_form_request_and_confirmation():
    session = object()
    with patch("py_nationalgrid.oidchelper._fetch", new_callable=AsyncMock) as fetch:
        fetch.return_value = ('{"status":"200"}', None, 200)
        await _post_credentials(
            session,
            ISSUER,
            SETTINGS,
            "synthetic-user",
            "synthetic-password",
            POLICY,
            NationalGridAuth.SELF_ASSERTED_ENDPOINT,
            30,
        )
        args, kwargs = fetch.call_args
        assert (
            args[1]
            == f"https://login.nationalgrid.com/login.nationalgridus.com/{POLICY}/SelfAsserted"
        )
        assert kwargs["params"] == {"tx": SETTINGS["transId"], "p": POLICY}
        assert kwargs["data"] == {
            "request_type": "RESPONSE",
            "signInName": "synthetic-user",
            "password": "synthetic-password",
            "Signin-forgotPassword": "FORGOT_PASSWORD_FALSE",
        }
        assert kwargs["headers"]["X-CSRF-TOKEN"] == SETTINGS["csrf"]
        assert kwargs["headers"]["Origin"] == "https://login.nationalgrid.com"
        assert kwargs["headers"]["X-Requested-With"] == "XMLHttpRequest"
        fetch.return_value = ("", NationalGridAuth.REDIRECT_URI + "?code=synthetic-code", 200)
        code, _ = await _confirm_signin(
            session,
            ISSUER,
            SETTINGS,
            POLICY,
            NationalGridAuth.POLICY_CONFIRM_ENDPOINT,
            NationalGridAuth.REDIRECT_URI,
            {},
            NationalGridAuth.CLIENT_ID,
            30,
        )
        assert code == "synthetic-code"
        assert fetch.call_args.args[1].endswith("/api/SelfAsserted/confirmed")
        assert NationalGridAuth.SCOPE_AUTH == NationalGridAuth.SCOPE_ACCESS


@pytest.mark.parametrize(
    "path",
    [
        "//other.example/tenant",
        "https://other.example/tenant",
        "/tenant?query=1",
        "/tenant#fragment",
    ],
)
def test_form_tenant_cannot_redirect_credentials_to_another_host(path):
    with pytest.raises(CannotConnectError, match="Invalid authentication form tenant path"):
        _form_endpoint(ISSUER, {"hosts": {"tenant": path}}, POLICY, "SelfAsserted")


def test_legacy_form_path_without_hosts():
    assert (
        _form_endpoint(ISSUER, {}, POLICY, "SelfAsserted")
        == f"https://login.nationalgrid.com/tenant-id/{POLICY}/SelfAsserted"
    )


@pytest.mark.asyncio
async def test_oauth_transport_keeps_cookie_domain_path_and_secure_scope():
    secret = "synthetic-session-secret"
    observed = []
    real_client = httpx.AsyncClient

    def handle(request):
        observed.append(request)
        if request.url.host == "login.example" and request.url.path == "/auth/start":
            assert secret in request.headers["cookie"]
            return httpx.Response(
                302,
                headers={
                    "location": "https://callback.example/landing",
                    "set-cookie": "new_session=synthetic-new; Path=/auth; Secure; HttpOnly",
                },
            )
        assert "cookie" not in request.headers
        return httpx.Response(200, text="completed")

    def client(**kwargs):
        assert kwargs["verify"] is True
        assert kwargs["trust_env"] is False
        return real_client(**kwargs, transport=httpx.MockTransport(handle))

    async with aiohttp.ClientSession() as session:
        from http.cookies import SimpleCookie

        cookies = SimpleCookie()
        cookies.load(f"private_session={secret}; Path=/auth; Secure; HttpOnly")
        session.cookie_jar.update_cookies(cookies, URL("https://login.example/auth/start"))
        with patch("py_nationalgrid.oidchelper.httpx.AsyncClient", side_effect=client):
            body, final_url, status = await _fetch(session, "https://login.example/auth/start", 30)
            assert (body, final_url, status) == (
                "completed",
                "https://callback.example/landing",
                200,
            )
            await _fetch(session, "http://login.example/auth/plain", 30)
            await _fetch(session, "https://login.example/outside", 30)
        assert len(observed) == 4
        stored = {cookie.key: cookie for cookie in session.cookie_jar}
        assert stored["new_session"]["domain"] == "login.example"
        assert stored["new_session"]["secure"]
        assert stored["new_session"]["path"] == "/auth"
        assert not session.closed


@pytest.mark.asyncio
async def test_transport_failure_does_not_expose_private_url_or_nested_error(caplog):
    real_client = httpx.AsyncClient

    def handle(request):
        raise httpx.ConnectError("synthetic-private-token", request=request)

    def client(**kwargs):
        return real_client(**kwargs, transport=httpx.MockTransport(handle))

    async with aiohttp.ClientSession() as session:
        with patch("py_nationalgrid.oidchelper.httpx.AsyncClient", side_effect=client):
            with pytest.raises(CannotConnectError) as caught:
                await _fetch(session, "https://login.example/?code=synthetic-private-token", 30)
    assert "synthetic-private-token" not in str(caught.value)
    assert "synthetic-private-token" not in caplog.text
    assert caught.value.__suppress_context__


@pytest.mark.asyncio
async def test_oauth_hides_third_party_logs_without_hiding_unrelated_requests(caplog):
    caplog.set_level(logging.DEBUG)
    secret = "synthetic-private-auth-token"
    real_client = httpx.AsyncClient
    # This logger exists when a real AsyncClient constructs its httpcore transport.
    core_logger = logging.getLogger("httpcore.http11")

    def handle(request):
        core_logger.debug("received private Location/cookie: %s", secret)
        return httpx.Response(200, text="completed")

    def client(**kwargs):
        return real_client(**kwargs, transport=httpx.MockTransport(handle))

    async with aiohttp.ClientSession() as session:
        with patch("py_nationalgrid.oidchelper.httpx.AsyncClient", side_effect=client):
            await _fetch(session, f"https://login.example/?code={secret}", 30)
    assert secret not in caplog.text
    assert not any(r.name.startswith(("httpx", "httpcore")) for r in caplog.records)
    core_logger.debug("unrelated transport operation")
    async with real_client(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as public:
        await public.get("https://public.example/allowed")
    assert "unrelated transport operation" in caplog.text
    assert "https://public.example/allowed" in caplog.text
