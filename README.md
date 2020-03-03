# Python Requests session for authenticating with Microsoft (MSAL/ADAL)

## About

`requests_ms_auth` is a [Requests](https://requests.readthedocs.io/en/master/) compatible session class that you can use to authenticate with Microsoft either over [Azure Active Directory Authentication Library (ADAL)](https://adal-python.readthedocs.io/en/latest) or [Microsoft Authentication Library (MSAL)](https://msal-python.readthedocs.io/en/latest).

The package is available on [PyPi](https://pypi.org/project/requests-ms-auth/), the code is available on (github)[https://github.com/equinor/requests_ms_auth].

## How to use

### 1. Install the package

```bash
# Use pip to install the package
python3 -m pip install --upgrade requests_ms_auth
```

### 2. Import the class:

```python
# Import the session class
from requests_ms_auth import MsRequestsSession:
```

### 3. Prepare credentials

```python
# Prepare your credentials in a dict
auth_config = {
    # The Azure resource ID
    resource: "12345678-1234-1234-1234-123456789abc"
    # The Azure tenant ID
    tenant: "12345678-1234-1234-1234-123456789abc"
    # The Azure authority host URL
    authority_host_url: "https://login.microsoftonline.com"
    # The service client ID
    client_id: "12345678-1234-1234-1234-123456789abc"
    # The service secret
    client_secret: "this is a very secret secret key"
    # (Optional) An endpoint that should return 200 on get with these credentials
    #            (for quickly verifying that auth works)
    verification_url: "https://your.service.example.com/your/api/path"
}

```

### 4. Instanciate a session from the class and use it:

```python
# Instanciate the class with authentication dict as parameters
session = MsRequestsSession(auth_config)

# Use the session as you would use any other Requests session
res = session.get( "https://your.service.example.com/your/api/path")
```

### 5. Profit!

The session should automatically fetch a token on startup and when the last token expires. It will also verify itself in the constructor using the optional `verification_url` if specified, allowing you to terminate early on failure.

## Implementation details

The library uses `pip-compile` with `requirements.in` to manage and pin requirements. Requirements for test are maintained in a separate `test_rquirements.in`.

The library uses a Makefile to manage building, packaging and uploading of versions, as well as many short-cuts for running tests, compiling requirements and more. To get a menu simply invoke it with out target like this:

```bash
# Invoke the makefile without targets to see a menu of available targets
make
```

The library is built by github actions.

The library defaults to MSAL and can be told to use ADAL as an option.



## License

Please see [LICENSE](https://github.com/equinor/requests_ms_auth/LICENSE) file for details. requests_ms_auth is licensed under GNU AFFERO GENERAL PUBLIC LICENSE and has G-Faps.

## History

This project grew from the need of the [latigo](https://github.com/equinor/latigo) project.
