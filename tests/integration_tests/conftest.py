from copy import deepcopy
from os import environ

import pytest
from requests_ms_auth import MsRequestsSession
from requests_ms_auth.ms_session_config import MsSessionConfig


INTEGRATION_TENANT = environ["INTEGRATION_TENANT"]
INTEGRATION_CLIENT_ID = environ["INTEGRATION_CLIENT_ID"]
INTEGRATION_CLIENT_SECRET = environ["INTEGRATION_CLIENT_SECRET"]
INTEGRATION_RESOURCE = environ["INTEGRATION_RESOURCE"]
INTEGRATION_AUTHORITY_HOST_URL = environ["INTEGRATION_AUTHORITY_HOST_URL"]
INTEGRATION_LIVE_VERIFICATION_URL = environ["INTEGRATION_LIVE_VERIFICATION_URL"]

AUTH = MsSessionConfig(
    resource=INTEGRATION_RESOURCE,
    tenant=INTEGRATION_TENANT,
    authority_host_url=INTEGRATION_AUTHORITY_HOST_URL,
    client_id=INTEGRATION_CLIENT_ID,
    client_secret=INTEGRATION_CLIENT_SECRET,
    do_adal=True,
)


@pytest.fixture(scope="function")
def new_session():
    session_config = deepcopy(AUTH)
    return MsRequestsSession(msrs_auth_config=session_config)
