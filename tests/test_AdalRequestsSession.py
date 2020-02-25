import requests_adal_auth


def test_AdalRequestsSession():
    session = requests_adal_auth.AdalRequestsSession(
    {"client_id": "bob",
    "client_secret": "bob",
    "tenant": "bob",
    "resource_uri": "https://bob.com",
    "authority_host_url": "https://bob.com",
    "raa_redirect_uri": "https://bob.com",
    })
    #session.get("https://equinor.com")
