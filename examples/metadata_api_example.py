# do not forget to install this -> https://github.com/equinor/requests_ms_auth
from requests_ms_auth import MsRequestsSession, MsSessionConfig

if __name__ == "__main__":
    # replace credentials below:
    auth = {
        "tenant": "REPLACE",
        "client_id": "REPLACE",
        "client_secret": "REPLACE",
        "resource": "REPLACE",
        "authority_host_url": "REPLACE",
        "auto_adding_headers": {"Ocp-Apim-Subscription-Key": "REPLACE"},
        "verification_url": "REPLACE",
    }

    session_config = MsSessionConfig(**auth)  # create config for the session
    session = MsRequestsSession(session_config)  # initiate session object

    res = session.get("https://aurora15.shared.aurora.equinor.com/omnia-prevent/ready")
    print(f"[RESPONSE] {res.status_code} {res.text}")
    assert res.text == "Ok"
