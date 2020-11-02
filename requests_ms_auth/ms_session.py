import logging
from copy import deepcopy
from typing import Dict, Optional, Tuple, Union

import adal
import msal
import requests
import requests_oauthlib
import simplejson
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import NewConnectionError

from requests_ms_auth.ms_backend_application_client import MsBackendApplicationClient
from requests_ms_auth.ms_session_config import MsSessionConfig

logger = logging.getLogger(__name__)


class MsRequestsSession(requests_oauthlib.OAuth2Session):
    """A wrapper for OAuth2Session that also implements adal/msal token fetch.

    See https://requests.readthedocs.io/en/latest/_modules/requests/sessions/#Session
    See https://requests-oauthlib.readthedocs.io/en/latest/api.html#oauth-2-0-session
    See https://adal-python.readthedocs.io/en/latest/
    """

    msrs_aouth_header = "Authorization"
    msrs_access_token_name = "access_token"

    def __init__(self, msrs_auth_config: Union[MsSessionConfig, dict]):
        if not isinstance(msrs_auth_config, MsSessionConfig):  # TODO remove this in the future versions
            logger.warning("Using of 'msrs_auth_config' as dict will be deprecated in the next versions.")
            msrs_auth_config = MsSessionConfig(**msrs_auth_config)

        self.msrs_client_id = msrs_auth_config.client_id
        self.msrs_do_adal = msrs_auth_config.do_adal
        self.msrs_client_secret = msrs_auth_config.client_secret
        self.msrs_resource_uri = msrs_auth_config.resource
        self.msrs_tenant = msrs_auth_config.tenant
        self.msrs_validate_authority = self.msrs_tenant != "adfs"
        self.msrs_scope = msrs_auth_config.scope
        self.auto_adding_headers = msrs_auth_config.auto_adding_headers
        self.msrs_verification_url = msrs_auth_config.verification_url
        self.msrs_verify_on_startup = msrs_auth_config.verify_on_startup
        self.msrs_verification_element = msrs_auth_config.verification_element
        self.msrs_auto_refresh_url = f"{msrs_auth_config.authority_host_url}/{self.msrs_tenant}"
        self.msrs_token = self._fetch_access_token()
        if not self.msrs_token:
            raise Exception("Could not generate 'msrs_token'")
        self.msrs_client = MsBackendApplicationClient(
            client_id=self.msrs_client_id, token=self.msrs_token, scope=self.msrs_scope
        )
        logging.debug(
            f"__init__(client_id={self.msrs_client_id}, auto_refresh_url={self.msrs_auto_refresh_url}, "
            f"scope={self.msrs_scope})."
        )

        super(MsRequestsSession, self).__init__(client=self.msrs_client, token=self.msrs_token)

        if self.msrs_verify_on_startup:
            validation_ok, validation_error = self.verify_auth()
            if not validation_ok:
                raise Exception(validation_error)

    def _fetch_access_token(self) -> Dict:
        if self.msrs_do_adal:
            return self._fetch_access_token_adal()
        else:
            return self._fetch_access_token_msal()

    def _fetch_access_token_msal(self) -> Dict:
        self.msrs_ms_token = None
        self.msrs_oathlib_token = None
        try:
            context = msal.ConfidentialClientApplication(
                authority=self.msrs_auto_refresh_url,
                validate_authority=self.msrs_validate_authority,
                client_id=self.msrs_client_id,
                client_credential=self.msrs_client_secret,
            )
            scopes = [f"{self.msrs_resource_uri}/.default"]
            self.msrs_ms_token = context.acquire_token_for_client(scopes=scopes)
            if self.msrs_ms_token:
                if self.msrs_ms_token.get("error"):
                    error = self.msrs_ms_token.get("error")
                    desc = self.msrs_ms_token.get("error_description")
                    raise Exception(f"Error fetching MSAL token ({error}): {desc}")
                self.msrs_oathlib_token = {
                    "access_token": self.msrs_ms_token.get("access_token", ""),
                    "refresh_token": self.msrs_ms_token.get("refresh_token", ""),
                    "token_type": self.msrs_ms_token.get("token_type", "Bearer"),
                    "expires_in": self.msrs_ms_token.get("expires_in", 0),
                    "ext_expires_in": self.msrs_ms_token.get("ext_expires_in", 0),
                }
            else:
                logger.error(f"Could not get token for client {self.msrs_auto_refresh_url}")
                raise Exception("No token acquired")
            if not self.msrs_oathlib_token.get("access_token"):
                logger.warning("Token aqcuired seems lacking")
                raise Exception("Token aqcuired seems lacking")
        except Exception as e:
            logger.error(f"Error fetching token: {e}", exc_info=True)
            logger.warning(f"NOTE: {self}")
            raise e
        return self.msrs_oathlib_token

    def _fetch_access_token_adal(self) -> Dict:
        self.msrs_ms_token = None
        self.msrs_oathlib_token = None
        try:
            context = adal.AuthenticationContext(
                authority=self.msrs_auto_refresh_url, validate_authority=self.msrs_validate_authority, api_version=None
            )
            self.msrs_ms_token = (
                context.acquire_token_with_client_credentials(
                    self.msrs_resource_uri, self.msrs_client_id, self.msrs_client_secret
                )
                or {}
            )
            if self.msrs_ms_token:
                self.msrs_oathlib_token = {
                    self.msrs_access_token_name: self.msrs_ms_token.get("accessToken", ""),
                    "refresh_token": self.msrs_ms_token.get("refreshToken", ""),
                    "token_type": self.msrs_ms_token.get("tokenType", "Bearer"),
                    "expires_in": self.msrs_ms_token.get("expiresIn", 0),
                }
            else:
                logger.error(f"Could not get token for client {self.msrs_auto_refresh_url}")
                raise Exception("No token acquired")
        except Exception as e:
            logger.error(f"Error fetching token: {e}", exc_info=True)
            logger.warning(f"NOTE: {self}")
            raise e
        return self.msrs_oathlib_token

    def verify_auth(self) -> Tuple[bool, Optional[str]]:
        if self.msrs_verification_url:
            logger.debug("Verification URL specified, performing http verification")
            res = self.get(self.msrs_verification_url)
            if res is None:
                return False, "Verification failed: No response object returned"
            if not res:
                try:
                    res.raise_for_status()
                except requests.exceptions.HTTPError:
                    return False, f"Verification failed: Request returned HTTP {res.status_code} ({res.reason})"
            if self.msrs_verification_element:
                logger.debug("Verification element specified, performing json result verification")
                if not res.text:
                    return False, "Verification failed: Request returned empty response"
                j = None
                try:
                    j = res.json()
                except simplejson.errors.JSONDecodeError:  # type: ignore
                    return False, f"Verification failed: Response was not json. Excerpt: '{res.text[0:100]}'..."
                if not j:
                    return False, "Verification failed: Returned json was empty"

                verification_element = j.get(self.msrs_verification_element, None)
                if verification_element is None:
                    return (
                        False,
                        f"Verification failed: Expected json element '{self.msrs_verification_element}' not "
                        + f"found in response.  Excerpt: '{res.text[0:100]}...'",
                    )
            else:
                logger.debug("No verification element specified, skipping json result verification")
        else:
            logger.debug("No verification URL specified, skipping http verification")
        # Success
        return True, None

    def prepare_request(self, request):
        logging.debug(f"prepare_request(method={request.method}, url='{request.url}').")
        return super(MsRequestsSession, self).prepare_request(request)

    def request(
        self, method, url, data=None, headers=None, withhold_token=False, client_id=None, client_secret=None, **kwargs
    ):
        """This method will be called each time smth should be sent

        Notes:
            if 'sent' method will be called directly, this method will be invoked if there's no 'token' in the headers
            'access token' validity will be checked/renewed as well
        """
        logging.debug(f"request(method={method}, url='{url}').")

        headers = self.add_auto_headers(headers)

        self.access_token_check_and_renew(headers)

        return super(MsRequestsSession, self).request(
            method=method,
            url=url,
            data=data,
            headers=headers,
            withhold_token=withhold_token,
            client_id=client_id,
            client_secret=client_secret,
            **kwargs,
        )

    def send(self, request, **kwargs):
        """Send prepared Request with auth token

        Notes:
            if there's no auth header or it's empty -> use inherited from oauth2 functionality to add token on requests
            'access token' validity will be checked/renewed as well
        """
        logging.debug(f"send(method={request.method}, url='{request.url}').")
        self.access_token_check_and_renew(request.headers)

        request.headers = self.add_auto_headers(request.headers)

        try:
            if request.headers is not None and request.headers.get(self.msrs_aouth_header, False):
                # send prepared Request if access token exists in the Request
                response = super().send(request, **kwargs)
            else:
                # make another call to get token into the header
                response = self.request(
                    method=request.method, url=request.url, data=request.body, headers=request.headers, **kwargs
                )
            logging.debug("Response head follows: -----------------------")
            logging.debug(response.content[0:200])
            return response
        except NewConnectionError as e:
            logger.error(f"Could not connect (method={request.method}, url='{request.url}'): {e}")
            raise e
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP STATUS CODE WAS: {e}")
            raise e
        except Exception as e:
            logger.error(f"Could not perform request(method={request.method}, url='{request.url}'): {e}", exc_info=True)
            raise e

    def access_token_check_and_renew(self, headers: Optional[CaseInsensitiveDict] = None) -> None:
        """Check if 'access token' expired and renew it if needed

        Args:
            headers: Request headers. You should pass it by link (not copy) for auth header to be deleted.
                If there's already existing header with old token - we need to delete it fo the future renew.
        """
        if self.msrs_client.is_access_token_expired():
            self.access_token_run_renewal(headers)

    def access_token_run_renewal(self, headers: Optional[CaseInsensitiveDict] = None) -> None:
        """Renew 'access token' for the Session and its Client instances.

        Args:
            headers: Request headers. You should pass it by link (not copy) for auth header to be deleted.
                If there's already existing header with old token - we need to delete it fo the future renew.
        """
        self.msrs_token = self._fetch_access_token()
        if not self.msrs_token:
            raise Exception("Could not fetch token")
        self.msrs_client.access_token = self.msrs_token[self.msrs_access_token_name]
        self.token = self.msrs_token

        try:
            del headers[self.msrs_aouth_header]  # type: ignore
        except (KeyError, TypeError):
            pass

    def add_auto_headers(self, headers: Optional[CaseInsensitiveDict] = None) -> Optional[CaseInsensitiveDict]:
        """Force to add 'auto_adding_headers' to the request. Might be needed for an auth.

        Args:
            headers: Request headers.

        Returns:
            Updated headers if 'auto_adding_headers' exists, otherwise same headers that were passed to the func.
        """
        if not self.auto_adding_headers:
            return headers

        if not headers:
            headers = deepcopy(self.auto_adding_headers)
        else:
            headers.update(self.auto_adding_headers)
        return headers

    def close(self):
        logging.debug("close().")
        return super(MsRequestsSession, self).close()

    def __repr__(self):
        return f"""{self.__class__.__name__} {{
    type:                 {'ADAL' if self.msrs_do_adal else 'MSAL'}
    client_id:            [hidden]
    resource_uri:         {self.msrs_resource_uri}
    client_secret:        [hidden]
    tenant:               {self.msrs_tenant}
    validate_authority:   {self.msrs_validate_authority}
    auto_refresh_url:     {self.msrs_auto_refresh_url}
    verification:         {self.msrs_verification_url}
        {f"for '{self.msrs_verification_element}'" if self.msrs_verification_element else ''}
}}
"""
