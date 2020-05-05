"""Config options for MsRequestsSession class"""
from dataclasses import dataclass, field
from typing import List, Optional

from oauthlib.common import CaseInsensitiveDict


@dataclass
class MsSessionConfig:
    """Dataclass-configuration for creating 'MsRequestsSession'

    Dataclass attributes:
        client_id: client ID.
        client_secret: client secret.
        tenant: ID of the authority for "authority_host_url" that is responsible for token issuing.
        verification_url: you service url to call.
        verification_element: key in json that should be returned in the response on the first json "level".
        verify_on_startup: when verification_url is specified the default is to perform verification in constructor.
                            verify_on_startup = False will skip verification even when url is specified. You can still
                            perform verification manually with the verify() method.
        do_adal: if True -> use 'adal' method to fetch access token; otherwise use 'MSAL'.
        resource: uri/identifier of the resource to which you're going to make calls to.
        authority_host_url: base authority to issuing the token.
        scope: scope of the permissions that will be given (for adal only).
        auto_adding_headers: headers that will be automatically added to each request made by the "session".
            Existing headers will be overwritten be headers in this field.
    """

    client_id: str
    client_secret: str
    tenant: str
    verification_url: Optional[str] = None
    verification_element: Optional[str] = None
    verify_on_startup: bool = True
    do_adal: bool = True
    resource: str = "https://management.core.windows.net/"
    authority_host_url: str = "https://login.microsoftonline.com"
    scope: List[str] = field(default_factory=lambda: ["read", "write"])
    auto_adding_headers: CaseInsensitiveDict = field(default_factory=lambda: CaseInsensitiveDict({}))
