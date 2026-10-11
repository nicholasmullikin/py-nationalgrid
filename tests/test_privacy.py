"""Secrets must not escape through public errors, reprs, or login logs."""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from py_nationalgrid.config import NationalGridConfig
from py_nationalgrid.exceptions import (
    DataExtractionError,
    GraphQLError,
    RestAPIError,
    RetryExhaustedError,
)
from py_nationalgrid.oidchelper import _get_auth_silent, _post_credentials

SECRET = "synthetic-secret-account-token"


def test_error_summaries_and_config_repr():
    errors = [
        GraphQLError(
            SECRET,
            endpoint=SECRET,
            query=SECRET,
            variables={"id": SECRET},
            status=500,
            original_error=ValueError(SECRET),
        ),
        RestAPIError(
            SECRET,
            url=SECRET,
            method="GET",
            response_text=SECRET,
            original_error=ValueError(SECRET),
        ),
        DataExtractionError(SECRET, path=SECRET, response_data={"account": SECRET}),
        RetryExhaustedError(SECRET, attempts=3, last_error=ValueError(SECRET)),
    ]
    for error in errors:
        assert SECRET not in str(error)
    config = NationalGridConfig(
        username=SECRET, password=SECRET, default_headers={"Authorization": SECRET}
    )
    assert SECRET not in repr(config)
    assert config.verify_ssl is True


@pytest.mark.asyncio
async def test_auth_redirect_and_backend_error_logs(caplog):
    caplog.set_level(logging.DEBUG)
    session = MagicMock()
    response = AsyncMock()
    response.status = 302
    response.headers = {
        "Location": f"https://myaccount.nationalgrid.com/auth-landing?code={SECRET}"
    }
    session.get.return_value.__aenter__.return_value = response
    with patch("py_nationalgrid.oidchelper._extract_auth_result", return_value=("code", None)):
        await _get_auth_silent(
            session,
            "https://login.nationalgrid.com",
            {},
            "https://myaccount.nationalgrid.com/auth-landing",
            {},
            "client",
            30,
        )
    assert SECRET not in caplog.text
    with patch(
        "py_nationalgrid.oidchelper._fetch",
        return_value=(f'var GLOBALEX = {{"Detail":"{SECRET}"}}', None, 200),
    ):
        with pytest.raises(Exception):
            await _post_credentials(
                session,
                "https://login.nationalgrid.com/a/b",
                {"transId": SECRET, "csrf": SECRET},
                SECRET,
                SECRET,
                "policy",
                "SelfAsserted",
                30,
            )
    assert SECRET not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
