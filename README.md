# Python Requests for OAuth2 with ADAL / MSAL with auto-renew access token

## About

This project provides a simple [Requests](https://requests.readthedocs.io/en/master/) compatible session that you can use to authenticate with Microsoft using he following:
* Azure Active Directory Authentication Library ([ADAL](https://adal-python.readthedocs.io/en/latest))
* Microsoft Authentication Library ([MSAL](https://msal-python.readthedocs.io/en/latest)). (**not finished, use ADAL instead**)

Session *renews access token automatically* (by default token expires each hour).  
The package is available on [PyPi](https://pypi.org/project/requests-ms-auth/).

## How to use

### Install the package

```bash
python3 -m pip install --upgrade requests_ms_auth
```

### Use an example

> NOTE: These examples are made for easy access to Equinor specific systems.  
> NOTE: Before using the example you should first fill the credentials inside the example file. 

| Description | Example code |
|-------------|-----------|
| Python code to access [Metadata API](https://github.com/equinor/omnia-prevent-mdapi) using session directly| [metadata_api_example.py](https://github.com/equinor/requests_ms_auth/blob/master/examples/metadata_api_example.py) |

The session should automatically fetch a token on startup and renew it when the token expires. 
Session will also verify itself in the constructor using the optional `verification_url` if specified, allowing you to terminate early on failure.

### Configuration 

Session configuration details might be found in the docstring [here](https://github.com/equinor/requests_ms_auth/blob/master/requests_ms_auth/ms_session_config.py)


## Implementation details

* The library uses `pip-compile` with `requirements.in` to manage and pin requirements. Requirements for test are maintained in a separate `test_rquirements.in`.

* The library uses a Makefile to manage building, packaging and uploading of versions, as well as many short-cuts for running tests, compiling requirements and more.

* The library is built and tested by github actions.

* The package is prepared and uploaded to PyPi by github actions.

* The library defaults to **ADAL** and can be told to use **MSAL** as an option.

* To supply OAuth2 compatability the library depends on
  * [Requests](https://requests.readthedocs.io/en/master/)
  * [Requests-OAuthlib](https://requests-oauthlib.readthedocs.io/en/latest/) 


## Tests

### Config env variables
Export following ENV variables (with previously replaced values):

- from shell:
```shell script
export INTEGRATION_TENANT=tenant
export INTEGRATION_CLIENT_ID=id
export INTEGRATION_CLIENT_SECRET=secret
export INTEGRATION_RESOURCE=resourse
export INTEGRATION_AUTHORITY_HOST_URL=authority
export INTEGRATION_LIVE_VERIFICATION_URL=verification
export INTEGRATION_LIVE_VERIFICATION_ELEMENT=element
```

- OR add env variables to Pycharm or other IDE (with previously added values):
```text
INTEGRATION_TENANT=tenant;INTEGRATION_CLIENT_ID=id;INTEGRATION_CLIENT_SECRET=secret;INTEGRATION_RESOURCE=resourse;INTEGRATION_AUTHORITY_HOST_URL=authority;INTEGRATION_LIVE_VERIFICATION_URL=verification;INTEGRATION_LIVE_VERIFICATION_ELEMENT=element;
```

- OR use `.env` file:
```.env
INTEGRATION_TENANT=tenant
INTEGRATION_CLIENT_ID=id
INTEGRATION_CLIENT_SECRET=secret
INTEGRATION_RESOURCE=resourse
INTEGRATION_AUTHORITY_HOST_URL=authority
INTEGRATION_LIVE_VERIFICATION_URL=verification
INTEGRATION_LIVE_VERIFICATION_ELEMENT=element
```

### Run tests
```
make test
```

## License

Please see [LICENSE](https://github.com/equinor/requests_ms_auth/blob/master/LICENSE) file for details. requests_ms_auth is licensed under GNU AFFERO GENERAL PUBLIC LICENSE and has G-Faps.

## History

This project grew from the needs of the [latigo](https://github.com/equinor/latigo) project.

## TODOs
- check if MSAL method works;
- cover crucial parts with tests;
- clear Makefile;
- handle TODOs in the code;
- enable mypy for examples dir.
 