from unittest import mock
import adal
import logging
import os
import pytest
import requests_ms_auth
import sys
import typing
import yaml

logger = logging.getLogger(__name__)


@pytest.fixture
def auth_config():
    return {
        "resource": "dummy-resource",
        "tenant": "dummy-tenant",
        "authority_host_url": "dummy-authority",
        "client_id": "dummy-client",
        "client_secret": "dummy-secret",
        "verification_url": "https://bob.com",
    }


def load_yaml(filename):
    if not os.path.exists(filename):
        return None, f"File did not exist: '{filename}'."
    with open(filename, "r") as stream:
        data = {}
        failure = None
        try:
            data = yaml.safe_load(stream)
        except Exception as e:
            logger.error(e)
            failure = e
            data = {}
        return data, failure


@pytest.fixture
def auth_config_live():
    data, error = load_yaml("secrets.yaml")
    if not data or error:
        raise Exception("Could not read secrets: {error}")
    return data["auth"]


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
            {
                "access_token": "dummy-token",
                "refresh_token": "",
                "token_type": "Bearer",
                "expires_in": 0,
            },
        ),
        # Empty token provided, get `oath` token of `None`
        (BAD_TOKEN, None),
    ],
)
def todo_test_fetch_access_token_functioning_adal(
    MockAuthenticationContext, auth_config_live, token, expected_oath_token
):
    """
    Test that Adal auth token values result in expected OAuth tokens
    """

    mock_auth_context = MockAuthenticationContext(
        authority="https://dummy-authority", validate_authority=None, api_version=None
    )

    mock_auth_context.acquire_token_with_client_credentials.return_value = token
    session = requests_ms_auth.MsRequestsSession(auth_config)
    assert session._fetch_access_token() == expected_oath_token


@mock.patch("adal.AuthenticationContext", autospec=True)
def todo_test_fetch_access_token_malfunctioning_adal(
    MockAuthenticationContext, auth_config
):
    """
    Test that when adal methods error, Exception is raises
    """
    # Context retrieval success, token retrieval method errors
    mock_auth_context = MockAuthenticationContext(
        authority="https://dummy-authority", validate_authority=None, api_version=None
    )
    mock_auth_context.acquire_token_with_client_credentials.side_effect = Exception
    with pytest.raises(Exception):
        fetch_access_token(auth_config)

    # Context generation errors
    MockAuthenticationContext.side_effect = Exception
    with pytest.raises(Exception):
        fetch_access_token(auth_config)


@mock.patch("requests_ms_auth.OAuth2Session", autospec=True)
@mock.patch("requests_ms_auth.adal.AuthenticationContext", autospec=True)
def todo_test_create_auth_session(
    MockAuthenticationContext, MockOAuth2Session, auth_config
):
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
    assert create_auth_session(auth_config)

    # OAuth token retrieved, session creation throws exception, return session of `None`
    MockOAuth2Session.side_effect = Exception
    mock_auth_context.acquire_token_with_client_credentials.return_value = BAD_TOKEN
    assert create_auth_session(auth_config) is None

    # OAuth token not retrieved, return session of `None`
    mock_auth_context.acquire_token_with_client_credentials.return_value = BAD_TOKEN
    assert create_auth_session(auth_config) is None


def todo_test_MsRequestsSession(auth_config_live):
    session = requests_ms_auth.MsRequestsSession(auth_config_live)
    ok, message = session.verify_auth()
    assert ok


def test_true():
    assert True == True
