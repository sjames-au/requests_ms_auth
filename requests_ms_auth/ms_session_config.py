"""Config options for MsRequestsSession class"""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class MsSessionConfig:
    """Dataclass-configuration for creating 'MsRequestsSession'

    Dataclass attributes:
        client_id: client ID
        client_secret: client secret
        verification_url: you service url to call
        verification_element: key in json that should be returned in the response on the first json "level"
        do_adal: if True -> use 'adal' method to fetch access token; otherwise use 'MSAL'
        resource: uri/identifier of the resource to which you're going to make calls to
        authority_host_url: base authority to issuing the token
        tenant: ID of the authority for "authority_host_url" that is responsible for token issuing
        scope: scope of the permissions that will be given
    """

    client_id: str
    client_secret: str
    verification_url: Optional[str] = None
    verification_element: Optional[str] = None
    do_adal: bool = False
    resource: str = "https://management.core.windows.net/"
    authority_host_url: str = "https://login.microsoftonline.com"
    tenant: str = "adfs"
    scope: List[str] = field(default_factory=lambda: ["read", "write"])
