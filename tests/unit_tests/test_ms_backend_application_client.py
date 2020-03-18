"""tests for MsBackendApplicationClient class"""
from time import time as time_now

import pytest
from mock import patch


@pytest.mark.parametrize("increase_to_time_now,expected", [(3586, True), (3575, False), (1, False)])
def test_is_access_token_expired(increase_to_time_now: int, expected: bool, backend_client):
    """Explanation: '3586' ~ '59,76667' minutes, so we increase time() with it and check for expiration"""
    with patch("requests_ms_auth.ms_backend_application_client.time.time") as time_mock:
        time_mock.return_value = time_now() + increase_to_time_now  # adjust time() for comparing with '_expire_at'

        res = backend_client.is_access_token_expired()
        assert res is expected
