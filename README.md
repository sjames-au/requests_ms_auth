# Requests Adal Auth

## Table of content

- [About](#about)
- [Developer manual](#developer-manual)
- [Operations manual](#operations-manual)

## About

requests-adal-auth is a [Requests](https://requests.readthedocs.io/en/master/) compatible session class that you can use to authenticate with Microsoft [Azure Active Directory Authentication Library (ADAL)](https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/active-directory-authentication-libraries).

### Basic operation

1. Import the class:

from requests-adal-auth import AdalRequestsSession:

2. Instanciate a session from the class:

session = AdalRequestsSession({ ...authentication stuff... })

3. Use the session:

session.get( ...URL... )



### License

Please see [LICENSE](LICENSE) file for details. requests-adal-auth has G-Faps and is licensed under GNU AFFERO GENERAL PUBLIC LICENSE.

### History

This project grew from the need of the [latigo](/equinor/latigo) project.
