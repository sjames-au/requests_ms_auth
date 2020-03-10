#!/usr/bin/env python

# To run this example, please do the following:
#
# 1. install requirements using the following command:
# python -m pip install --upgrade -r requirements.in
#
# 2. Insert your actual credentials in the time_series_api_credentials.yaml file
#
# 3. Run the script from Pyhton3.7 environment:
# ./time_series_api_example.py

from requests_ms_auth import MsRequestsSession
import logging
import pprint
import yaml

# Set default log level to "INFO"
from requests_ms_auth.ms_session_config import MsSessionConfig

logging.basicConfig(level=logging.INFO)

# Create the logger we will use
logger = logging.getLogger(__file__)

# Main program entry point
if __name__ == "__main__":

    # 1. Load credentials from file (never store credentials in git)!
    filename = "time_series_api_credentials.yaml"
    logger.info(f"Loading credentials from {filename}")
    with open(filename, "r") as stream:
        auth_config = MsSessionConfig(**yaml.safe_load(stream))
    logger.info("Loaded credentials:\n" + pprint.pformat(auth_config))

    # 2.Instanciate a session with authentication dict as parameters
    session = MsRequestsSession(msrs_auth_config=auth_config)
    logger.info("Created session:\n" + str(session))

    # 3. Make a call to time series api using our session
    base_url = "https://api.gateway.equinor.com/plant/timeseries/v1.5"
    body = {"name": "PT-13005/MeasA/PRIM", "assetId": "SFB"}
    res = session.get(base_url, params=body)
    logger.info("Data from time series API:\n" + pprint.pformat(res.json()))
