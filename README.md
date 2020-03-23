# Python Requests for OAuth2 + MSAL / ADAL

## About

This project provides a simple [Requests](https://requests.readthedocs.io/en/master/) compatible session that you can use to authenticate with Microsoft using he following:
* Azure Active Directory Authentication Library ([ADAL](https://adal-python.readthedocs.io/en/latest))
* Microsoft Authentication Library([MSAL](https://msal-python.readthedocs.io/en/latest)).

The package is available on [PyPi](https://pypi.org/project/requests-ms-auth/) and the code is available on [github](https://github.com/equinor/requests_ms_auth).

## How to use

### 1. Install the package

```bash
# Use pip to install the package
python3 -m pip install --upgrade requests_ms_auth
```

### 2. Import the class:

```python
# Import the session class into your code
from requests_ms_auth import MsRequestsSession:
```

### 3. Prepare credentials

```python
# Prepare your credentials in a dict (or load it from yaml/json etc).
auth_config = {

    # The Azure resource ID  [required]
    resource: "12345678-1234-1234-1234-123456789abc",

    # The Azure tenant ID  [required]
    tenant: "12345678-1234-1234-1234-123456789abc",

    # The client ID  [required]
    client_id: "12345678-1234-1234-1234-123456789abc",

    # The client secret  [required]
    client_secret: "this is a very secret secret key",

    ## Optional arguments

    # Select ADAL over MSAL [optional]
    # NOTE: MSAL is default and preferred
    do_adal: False,

    # An endpoint that should return 200 when auth works [optional]
    verification_url: "https://your.service.example.com/your/api/verify_endpoint",

    # A json element name that should be in the top level of response body for verification_url [optional]
    verification_element: "data",
}
```

### 4. Instanciate a session from the class and use it:

```python
# Instanciate the class with authentication dict as parameters
session = MsRequestsSession(auth_config)

# Use the session as you would use any other Requests session
res = session.get( "https://your.service.example.com/your/api/useful_thingy")
```

### 5. Profit!

The session should automatically fetch a token on startup and when the last token expires. It will also verify itself in the constructor using the optional `verification_url` if specified, allowing you to terminate early on failure.

## Implementation details

* The library uses `pip-compile` with `requirements.in` to manage and pin requirements. Requirements for test are maintained in a separate `test_rquirements.in`.

* The library uses a Makefile to manage building, packaging and uploading of versions, as well as many short-cuts for running tests, compiling requirements and more. To get a menu simply invoke it with out target like this:

```bash
# Invoke the makefile without targets to see a menu of available targets
make
```

* The library is built and tested by github actions.

* The package is prepared and uploaded to PyPi by github actions.

* The library defaults to **MSAL** and can be told to use **ADAL** as an option.

* To supply OAuth2 compatability the library depends on
  * [Requests](https://requests.readthedocs.io/en/master/)
  * [Requests-OAuthlib](https://requests-oauthlib.readthedocs.io/en/latest/) 

## Examples

> NOTE: These examples are made for easy access to Equinor spesific systems, but should still illustrate general usage.

| Description | Example code |
|-------------|-----------|
| Python code to access [Time Series API](https://github.com/equinor/OmniaPlant/tree/master/Omnia%20Timeseries%20API) using session directly| [time_series_api_example.py](https://github.com/equinor/requests_ms_auth/blob/master/examples/time_series_api_example.py) |
| Python code to access [Gordo](https://github.com/equinor/gordo) using the Gordo Client | [gordo_example.py](https://github.com/equinor/requests_ms_auth/blob/master/examples/gordo_example.py) |

### 6. Tests
To run tests - export following ENV variables (with previously replaced values):
```shell script
export INTEGRATION_TENANT=tenent
export INTEGRATION_CLIENT_ID=id
export INTEGRATION_CLIENT_SECRET=secret
export INTEGRATION_RESOURCE=resourse
export INTEGRATION_AUTHORITY_HOST_URL=authority
export INTEGRATION_LIVE_VERIFICATION_URL=verification
export INTEGRATION_LIVE_VERIFICATION_ELEMENT=element
```

OR add env variables to Pycharn or other IDE (with previously added values):
```text
INTEGRATION_TENANT=;INTEGRATION_CLIENT_ID=;INTEGRATION_CLIENT_SECRET=;INTEGRATION_RESOURCE=;INTEGRATION_AUTHORITY_HOST_URL=;INTEGRATION_LIVE_VERIFICATION_URL=;INTEGRATION_LIVE_VERIFICATION_ELEMENT=;
```

Then run:
```
make test
```

## License

Please see [LICENSE](https://github.com/equinor/requests_ms_auth/blob/master/LICENSE) file for details. requests_ms_auth is licensed under GNU AFFERO GENERAL PUBLIC LICENSE and has G-Faps.

## History

This project grew from the needs of the [latigo](https://github.com/equinor/latigo) project.
