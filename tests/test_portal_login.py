"""Match the consumer portal's observed October 2026 OAuth form requests."""

from unittest.mock import AsyncMock, patch

import pytest

from py_nationalgrid.auth import NationalGridAuth
from py_nationalgrid.exceptions import CannotConnectError
from py_nationalgrid.oidchelper import _confirm_signin, _form_endpoint, _post_credentials

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
        assert kwargs["headers"] == {"X-CSRF-TOKEN": SETTINGS["csrf"]}
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
