#!/usr/bin/env python

# To run this example, please do the following:
#
# 1. install requirements using the following command:
# python -m pip install --upgrade -r requirements.in
#
# 2. Insert your actual credentials in the gordo_credentials.yaml file
#
# 3. Run the script from Pyhton3.7 environment:
# ./gordo_example.py

from requests_ms_auth import MsRequestsSession
from gordo.client.client import Client
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
    auth_config = {}
    with open(filename, "r") as stream:
        auth_config = MsSessionConfig(**yaml.safe_load(stream))
    logger.info("Loaded credentials:\n" + pprint.pformat(auth_config))

    # 2. Instanciate a session with authentication dict as parameters
    session = MsRequestsSession(auth_config)

    # 3. Instanciate the Gordo client using our session
    client = Client(project="ioc-1901", host="ioc.dev.aurora.equinor.com", session=session)

    # 4. Use Gordo client to make sure it works
    revisions = client.get_revisions()
    logger.info(pprint.pformat(revisions))
