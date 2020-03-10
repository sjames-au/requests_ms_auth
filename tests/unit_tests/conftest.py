import pytest

from requests_ms_auth.ms_backend_application_client import MsBackendApplicationClient


@pytest.fixture(scope="function")
def backend_client() -> MsBackendApplicationClient:
    default_expire_in = 3599
    token = {"access_token": "foo", "refresh_token": "", "token_type": "Bearer", "expires_in": default_expire_in}
    return MsBackendApplicationClient(client_id="foo_id", token=token)
