# Python Requests session for authenticating with Microsoft (MSAL/ADAL)

## About

`requests_ms_auth` is a [Requests](https://requests.readthedocs.io/en/master/) compatible session class that you can use to authenticate with Microsoft either over [Azure Active Directory Authentication Library (ADAL)](https://adal-python.readthedocs.io/en/latest) or [Microsoft Authentication Library (MSAL)](https://msal-python.readthedocs.io/en/latest).

## Basic operation

### 1. Import the class:

```python
# Import the session class
from requests_ms_auth import MsRequestsSession:
```

### 2. Prepare credentials

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
    # (Optional) An endpoint that should return 200 on get with these credentials (for quickly verifying that auth works)
    verification_url: "https://your.service.example.com/your/api/path"
}

```

### 3. Instanciate a session from the class:

```python
# Instanciate the class with authentication dict as parameters
session = MsRequestsSession(auth_config)
```

### 4. Use the session:

```python
# Use the session as you would use any other Requests session
res = session.get( "https://your.service.example.com/your/api/path")
```

### 5. Profit!

The session should automatically fetch a token on startup and when the token expires. It will also verify itself using the optional verification_url if specified, allowing you to terminate early on failure.

## License

Please see [LICENSE](LICENSE) file for details. requests_adal_auth has G-Faps and is licensed under GNU AFFERO GENERAL PUBLIC LICENSE.

## History

This project grew from the need of the [latigo](/equinor/latigo) project.
