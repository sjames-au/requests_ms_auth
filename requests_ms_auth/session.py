import logging
import pprint
from simplejson.errors import JSONDecodeError
from typing import Optional, Dict, Tuple

import adal
import msal
import requests
import requests_oauthlib
from requests.structures import CaseInsensitiveDict
from requests_ms_auth.ms_backend_application_client import MsBackendApplicationClient

logger = logging.getLogger(__name__)


class MsRequestsSession(requests_oauthlib.OAuth2Session):
    """A wrapper for OAuth2Session that also implements adal token fetch.

    See https://requests.readthedocs.io/en/latest/_modules/requests/sessions/#Session
    See https://requests-oauthlib.readthedocs.io/en/latest/api.html#oauth-2-0-session
    See https://adal-python.readthedocs.io/en/latest/
    """

    msrs_aouth_header = "Authorization"
    msrs_access_token_name = "access_token"

    def __init__(self, auth_config):
        self._set_config(auth_config)
        self.msrs_state = None
        self.msrs_token = self._fetch_access_token()
        if not self.msrs_token:
            raise Exception("Could not generate token")
        # client=requests_oauthlib.WebApplicationClient(client_id=self.msrs_client_id, token=self.msrs_token)
        self.msrs_client = MsBackendApplicationClient(
            client_id=self.msrs_client_id,
            token=self.msrs_token,
            auto_refresh_url=self.msrs_auto_refresh_url,
            auto_refresh_kwargs=self.msrs_auto_refresh_kwargs,
            token_updater=self._token_saver,
            scope=self.msrs_scope,
        )
        logging.info(
            f"@@@ msrs: __init__(client_id={self.msrs_client_id}, auto_refresh_url={self.msrs_auto_refresh_url}, "
            f"scope={self.msrs_scope})."
        )
        super(MsRequestsSession, self).__init__(client=self.msrs_client, token=self.msrs_token)
        validation_ok, validation_error = self.verify_auth()
        if not validation_ok:
            raise Exception(validation_error)

    def _set_config(self, auth_config):
        self.msrs_auth_config = auth_config
        self.msrs_client_id = self.msrs_auth_config.get("client_id")
        self.msrs_do_adal = self.msrs_auth_config.get("do_adal", False)
        if not self.msrs_client_id:
            raise Exception("No client_id specified")
        self.msrs_client_secret = self.msrs_auth_config.get("client_secret")
        if not self.msrs_client_secret:
            raise Exception("No client_secret specified")
        self.msrs_resource_uri = self.msrs_auth_config.get("resource", "https://management.core.windows.net/")
        if not self.msrs_resource_uri:
            raise Exception("No resource_uri specified")
        self.msrs_authority_host_url = self.msrs_auth_config.get(
            "authority_host_url", "https://login.microsoftonline.com"
        )
        if not self.msrs_authority_host_url:
            raise Exception("No authority_host_url specified")
        self.msrs_tenant = self.msrs_auth_config.get("tenant", "adfs")
        if not self.msrs_tenant:
            raise Exception("No tenant specified")
        self.msrs_validate_authority = self.msrs_tenant != "adfs"
        self.msrs_scope = self.msrs_auth_config.get("scope", ["read", "write"])
        self.msrs_verification_url = self.msrs_auth_config.get("verification_url")
        self.msrs_verification_element = self.msrs_auth_config.get("verification_element")
        self.msrs_auto_refresh_url = f"{self.msrs_authority_host_url}/{self.msrs_tenant}"
        self.msrs_auto_refresh_kwargs = {
            "client_id": self.msrs_client_id,
            "client_secret": self.msrs_client_secret,
            "resource": self.msrs_resource_uri,
        }  # aka extra

    def _fetch_access_token(self) -> Optional[Dict]:
        if self.msrs_do_adal:
            return self._fetch_access_token_adal()
        else:
            return self._fetch_access_token_msal()

    def _fetch_access_token_msal(self) -> Optional[Dict]:
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
                raise Exception("No token aqcuired")
            if not self.msrs_oathlib_token.get("access_token"):
                logger.warning(f"Token aqcuired seems lacking")
                raise Exception("Token aqcuired seems lacking")
        except Exception as e:
            logger.error(f"Error fetching token: {e}", exc_info=True)
            logger.warning(f"NOTE: {self}")
            raise e
        return self.msrs_oathlib_token

    def _fetch_access_token_adal(self) -> Optional[Dict]:
        self.msrs_ms_token = None
        self.msrs_oathlib_token = None
        try:
            context = adal.AuthenticationContext(
                authority=self.msrs_auto_refresh_url, validate_authority=self.msrs_validate_authority, api_version=None,
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
            return self.msrs_oathlib_token
        except Exception as e:
            logger.error(f"Error fetching token: {e}", exc_info=True)
            logger.warning(f"NOTE: {self}")
            raise e
        return self.msrs_oathlib_token

    def _token_saver(self, token):
        logger.debug("@@@ msrs: Saving token: " + pprint.pformat(token))

    def verify_auth(self) -> Tuple[bool, Optional[str]]:
        if self.msrs_verification_url:
            logger.info("@@@ msrs: Verification URL specified, performing http verification")
            res = self.get(self.msrs_verification_url)
            if res is None:
                return False, "Verification failed: No response object returned"
            if not res:
                try:
                    res.raise_for_status()
                except requests.exceptions.HTTPError:
                    return False, f"Verification failed: Request returned HTTP {res.status_code} ({res.reason})"
            if self.msrs_verification_element:
                logger.debug("@@@ msrs: Verification element specified, performing json result verification")
                if not res.text:
                    return False, "Verification failed: Request returned empty response"
                j = None
                try:
                    j = res.json()
                except JSONDecodeError:
                    return False, f"Verification failed: Response was not json. Excerpt: '{res.text[0:100]}'..."
                if not j:
                    return False, "Verification failed: Returned json was empty"

                if not j.get(self.msrs_verification_element, False):
                    return (
                        False,
                        f"Verification failed: Expected json element '{self.msrs_verification_element}' not "
                        + f"found in response.  Excerpt: '{res.text[0:100]}...'",
                    )
            else:
                logger.debug(f"@@@ msrs: No verification element specified, skipping json result verification")
        else:
            logger.debug(f"@@@ msrs: No verification URL specified, skipping http verification")
        # Success
        return True, None

    def prepare_request(self, request):
        logging.debug(f"@@@ msrs: prepare_request(method={request.method}, url='{request.url}').")
        return super(MsRequestsSession, self).prepare_request(request)

    def request(
        self, method, url, data=None, headers=None, withhold_token=False, client_id=None, client_secret=None, **kwargs,
    ):
        """This method will be called each time smth should be sent

        Notes:
            if 'sent' method will be called directly, this method will be invoked if there's no 'token' in the headers
            'access token' validity will be checked/renewed as well
        """
        logging.debug(f"@@@ msrs: request(method={method}, url='{url}').")
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
        logging.debug(f"@@@ msrs: send(method={request.method}, url='{request.url}').")
        self.access_token_check_and_renew(request.headers)

        try:
            if request.headers is not None and request.headers.get(self.msrs_aouth_header, False):
                # send prepared Request if access token exists in the Request
                response = super().send(request, **kwargs)
            else:
                # make another call to get token into the header
                response = self.request(
                    method=request.method, url=request.url, data=request.body, headers=request.headers, **kwargs,
                )
            logging.debug(f"@@@ msrs: Response head follows: -----------------------")
            logging.debug(response.content[0:200])
            return response
        except requests.exceptions.NewConnectionError as e:
            logger.error(f"Could not connect (method={request.method}, url='{request.url}'): {e}")
            raise e
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP STATUS CODE WAS: {e}")
            raise e
        except Exception as e:
            logger.error(
                f"Could not perform request(method={request.method}, url='{request.url}'): {e}", exc_info=True,
            )
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

    def close(self):
        logging.debug(f"@@@ msrs: close().")
        return super(MsRequestsSession, self).close()

    def __repr__(self):
        return f"""{self.__class__.__name__}: {{
    "type":                 "{'ADAL' if self.msrs_do_adal else 'MSAL'}",
    "client_id":            "{self.msrs_client_id}",
    "resource_uri":         "{self.msrs_resource_uri}",
    "client_secret":        "hidden",
    "tenant":               "{self.msrs_tenant}",
    "validate_authority":   {"true" if self.msrs_validate_authority else "false"},
    "authority_host_url":   "{self.msrs_authority_host_url}",
    "auto_refresh_url":     "{self.msrs_auto_refresh_url}",
    "verification_url":     "{self.msrs_verification_url}",
    "verification_element": "{self.msrs_verification_element}",
}}
"""
