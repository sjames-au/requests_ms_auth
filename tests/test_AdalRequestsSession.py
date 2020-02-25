import requests_adal_auth

def test_AdalRequestsSession():
    session = requests_adal_auth.AdalRequestsSession({'test':'bob'})
    session.get("https://equinor.com")
