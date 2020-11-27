"""tests for MsBackendApplicationClient class"""
from time import time as time_now

import pytest
from mock import patch


@pytest.mark.parametrize("increase_to_time_now,is_token_expired", [(3540, True), (3534, False), (1, False)])
def test_is_access_token_expired(increase_to_time_now: int, is_token_expired: bool, backend_client):
    """Explanation: '3534' ~ '58,9' minutes, so we increase time() with it and check for expiration."""
    with patch("requests_ms_auth.ms_backend_application_client.time.time") as time_mock:
        time_mock.return_value = time_now() + increase_to_time_now  # adjust time() for comparing with '_expire_at'

        res = backend_client.is_access_token_expired()
        assert res is is_token_expired
