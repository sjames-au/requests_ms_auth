from unittest import mock
import adal
import logging
import os
import pytest
import requests_ms_auth
import typing
import json
import requests

logger = logging.getLogger(__name__)


@pytest.fixture
def auth_config_dummy():
    return {
        "resource": "dummy-resource",
        "tenant": "dummy-tenant",
        "authority_host_url": "dummy-authority",
        "client_id": "dummy-client",
        "client_secret": "dummy-secret",
        "verification_url": "https://bob.com",
    }


@pytest.fixture
def auth_config_live_msal():
    with open("secrets.json", "r") as file:
        data = json.load(file)
    return data[0]


@pytest.fixture
def auth_config_live_adal():
    with open("secrets.json", "r") as file:
        data = json.load(file)
    data = data[0]
    data["do_adal"] = True
    return data


# {
# "resource": "dummy-resource",
# "tenant": "dummy-tenant",
# "authority_host_url": "dummy-authority",
# "client_id": "dummy-client",
# "client_secret": "dummy-secret",
# "verification_url": "https://bob.com",
# }


VALID_TOKEN: typing.Dict[str, typing.Union[str, int]] = {
    "accessToken": "dummy-token",
    "refreshToken": "dummy-refresh",
    "tokenType": "dummy-type",
    "expiresIn": 1000,
}
BAD_TOKEN: typing.Dict[str, typing.Union[str, int]] = {}


@mock.patch("adal.AuthenticationContext", autospec=True)
@pytest.mark.parametrize(
    "token,expected_oath_token",
    [
        # When keys provided, remapped to `oath` key strings
        (
            VALID_TOKEN,
            {
                "access_token": "dummy-token",
                "refresh_token": "dummy-refresh",
                "token_type": "dummy-type",
                "expires_in": 1000,
            },
        ),
        # Single key provided, returns `oath` defaults for other keys
        (
            {"accessToken": "dummy-token"},
            {"access_token": "dummy-token", "refresh_token": "", "token_type": "Bearer", "expires_in": 0},
        ),
        # Empty token provided, get `oath` token of `None`
        (BAD_TOKEN, None),
    ],
)
def todo_test_fetch_access_token_functioning_adal(
    MockAuthenticationContext, auth_config_live_msal, token, expected_oath_token
):
    """
    Test that Adal auth token values result in expected OAuth tokens
    """

    mock_auth_context = MockAuthenticationContext(
        authority="https://dummy-authority", validate_authority=None, api_version=None
    )

    mock_auth_context.acquire_token_with_client_credentials.return_value = token
    session = requests_ms_auth.MsRequestsSession(auth_config_dummy)
    assert session._fetch_access_token() == expected_oath_token


@mock.patch("adal.AuthenticationContext", autospec=True)
def todo_test_fetch_access_token_malfunctioning_adal(MockAuthenticationContext, auth_config_dummy):
    """
    Test that when adal methods error, Exception is raises
    """
    # Context retrieval success, token retrieval method errors
    mock_auth_context = MockAuthenticationContext(
        authority="https://dummy-authority", validate_authority=None, api_version=None
    )
    mock_auth_context.acquire_token_with_client_credentials.side_effect = Exception
    with pytest.raises(Exception):
        fetch_access_token(auth_config_dummy)

    # Context generation errors
    MockAuthenticationContext.side_effect = Exception
    with pytest.raises(Exception):
        fetch_access_token(auth_config_dummy)


@mock.patch("requests_ms_auth.OAuth2Session", autospec=True)
@mock.patch("requests_ms_auth.adal.AuthenticationContext", autospec=True)
def todo_test_create_auth_session(MockAuthenticationContext, MockOAuth2Session, auth_config_dummy):
    """
    Test that OAuth session creation logic
    1. A valid token, and successful session creation returns the session
    2. A valid token, and failed session creation returns `None`.
    3. An invalid token, returns `None`
    """
    mock_auth_context = MockAuthenticationContext(
        authority="https://dummy-authority", validate_authority=None, api_version=None
    )

    # OAuth token retrieved, session created and returns
    MockOAuth2Session.side_effect = "valid-session"
    mock_auth_context.acquire_token_with_client_credentials.return_value = VALID_TOKEN
    assert create_auth_session(auth_config_dummy)

    # OAuth token retrieved, session creation throws exception, return session of `None`
    MockOAuth2Session.side_effect = Exception
    mock_auth_context.acquire_token_with_client_credentials.return_value = BAD_TOKEN
    assert create_auth_session(auth_config_dummy) is None

    # OAuth token not retrieved, return session of `None`
    mock_auth_context.acquire_token_with_client_credentials.return_value = BAD_TOKEN
    assert create_auth_session(auth_config_dummy) is None


# Make sure actually json was returned (HTTP 200 may indicate a web proxy web page being displayed)
def assert_json_response(res, element):
    # logger.warning(res)
    assert res.text
    j = res.json()
    assert j
    # logger.warning(j)
    data = j[element]
    assert data


def todo_test_all(auth_config_live_adal):
    with open("secrets.json", "r") as file:
        data = json.load(file)
    for auth in data:
        verification_url = auth["verification_url"]
        verification_element = auth["verification_element"]
        for do_adal in [True]:
            auth["do_adal"] = do_adal
            session = requests_ms_auth.MsRequestsSession(auth)
            logger.warning(f"Testing {session}")
            # Verification
            ok, message = session.verify_auth()
            assert ok
            logger.warning(f"Message: {message}")
            # Direct
            res = session.get(session.msrs_verification_url)
            assert_json_response(res, verification_element)
            # Prepared
            req = requests.Request("GET", verification_url)
            res = session.send(req.prepare())
            assert_json_response(res, verification_element)
