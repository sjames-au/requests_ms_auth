import logging

import requests
from requests import Response
from tests.integration_tests.conftest import INTEGRATION_LIVE_VERIFICATION_URL

logger = logging.getLogger(__name__)

MSRS_VERIFICATION_ELEMENT = "revision"


def test_session_verification_url(new_session):
    new_session.msrs_verification_url = INTEGRATION_LIVE_VERIFICATION_URL
    new_session.msrs_verification_element = MSRS_VERIFICATION_ELEMENT
    ok, message = new_session.verify_auth()
    assert ok


def test_session_get_method(new_session):
    res = new_session.get(INTEGRATION_LIVE_VERIFICATION_URL)
    assert_success_for_revision(res)


def test_session_send_method(new_session):
    request = requests.Request("GET", INTEGRATION_LIVE_VERIFICATION_URL)
    res = new_session.send(request.prepare())
    assert_success_for_revision(res)


def test_session_token_renew(new_session):
    expire_adjusting_seconds = 3600  # this is 60 minutes (default token expiration time)

    res = new_session.get(INTEGRATION_LIVE_VERIFICATION_URL)
    assert res.status_code == 200

    expired_token = "expired_token"
    new_session.access_token = expired_token
    new_session.msrs_client.access_token = expired_token
    new_session.msrs_client._expires_at -= expire_adjusting_seconds

    res = new_session.get(INTEGRATION_LIVE_VERIFICATION_URL)
    assert new_session.access_token != expired_token
    assert_success_for_revision(res)


def assert_success_for_revision(response: Response):
    """assert 200 response codee and existence of 'revision' in json response"""
    assert response.status_code == 200
    assert MSRS_VERIFICATION_ELEMENT in response.json()
