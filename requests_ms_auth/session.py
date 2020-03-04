import adal
import msal
import logging
import oauthlib.oauth2
import pprint
import requests
import requests_oauthlib
import typing
import json

logger = logging.getLogger(__name__)


class MsRequestsSession(requests_oauthlib.OAuth2Session):

    """
    A wrapper for OAuth2Session that also implements adal token fetch.
    See https://requests.readthedocs.io/en/latest/_modules/requests/sessions/#Session
    See https://requests-oauthlib.readthedocs.io/en/latest/api.html#oauth-2-0-session
    See https://adal-python.readthedocs.io/en/latest/
    """

    def __init__(self, auth_config):
        self.msrs_aouth_header = "Authorization"
        self._set_config(auth_config)
        self.msrs_state = None
        self.msrs_token = self._fetch_access_token()
        if not self.msrs_token:
            raise Exception("Could not generate token")
        # client=requests_oauthlib.WebApplicationClient(client_id=self.msrs_client_id, token=self.msrs_token)
        self.msrs_client = oauthlib.oauth2.BackendApplicationClient(
            client_id=self.msrs_client_id,
            token=self.msrs_token,
            auto_refresh_url=self.msrs_auto_refresh_url,
            auto_refresh_kwargs=self.msrs_auto_refresh_kwargs,
            token_updater=self._token_saver,
            scope=self.msrs_scope,
        )
        logging.info(
            f"@@@ msrs: __init__(client_id={self.msrs_client_id}, auto_refresh_url={self.msrs_auto_refresh_url}, scope={self.msrs_scope})."
        )
        super(MsRequestsSession, self).__init__(
            client=self.msrs_client, token=self.msrs_token
        )
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
        self.msrs_resource_uri = self.msrs_auth_config.get(
            "resource", "https://management.core.windows.net/"
        )
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
        self.msrs_verification_element = self.msrs_auth_config.get(
            "verification_element"
        )
        self.msrs_auto_refresh_url = (
            f"{self.msrs_authority_host_url}/{self.msrs_tenant}"
        )
        self.msrs_auto_refresh_kwargs = {
            "client_id": self.msrs_client_id,
            "client_secret": self.msrs_client_secret,
            "resource": self.msrs_resource_uri,
        }  # aka extra

    def _fetch_access_token(self) -> typing.Optional[typing.Dict]:
        if self.msrs_do_adal:
            return self._fetch_access_token_adal()
        else:
            return self._fetch_access_token_msal()

    def _fetch_access_token_msal(self) -> typing.Optional[typing.Dict]:
        self.msrs_ms_token = None
        self.msrs_oathlib_token = None
        try:
            context = msal.ConfidentialClientApplication(
                authority=self.msrs_auto_refresh_url,
                validate_authority=self.msrs_validate_authority,
                client_id=self.msrs_client_id,
                client_credential=self.msrs_client_secret,
            )
            self.msrs_ms_token = (
                context.acquire_token_for_client(scopes=[self.msrs_resource_uri]) or {}
            )
            if self.msrs_ms_token:
                if self.msrs_ms_token.get("error"):
                    error = self.msrs_ms_token.get("error")
                    desc = self.msrs_ms_token.get("error_description")
                    raise Exception(f"Error fetching MSAL token ({error}): {desc}")
                self.msrs_oathlib_token = {
                    "access_token": self.msrs_ms_token.get("accessToken", ""),
                    "refresh_token": self.msrs_ms_token.get("refreshToken", ""),
                    "token_type": self.msrs_ms_token.get("tokenType", "Bearer"),
                    "expires_in": self.msrs_ms_token.get("expiresIn", 0),
                }
            else:
                logger.error(
                    f"Could not get token for client {self.msrs_auto_refresh_url}"
                )
        except Exception as e:
            logger.error(f"Error fetching token: {e}", exc_info=True)
            logger.warning(f"NOTE: {self}")
            raise e
        return self.msrs_oathlib_token

    def _fetch_access_token_adal(self) -> typing.Optional[typing.Dict]:
        self.msrs_ms_token = None
        self.msrs_oathlib_token = None
        try:
            context = adal.AuthenticationContext(
                authority=self.msrs_auto_refresh_url,
                validate_authority=self.msrs_validate_authority,
                api_version=None,
            )
            self.msrs_ms_token = (
                context.acquire_token_with_client_credentials(
                    self.msrs_resource_uri, self.msrs_client_id, self.msrs_client_secret
                )
                or {}
            )
            if self.msrs_ms_token:
                self.msrs_oathlib_token = {
                    "access_token": self.msrs_ms_token.get("accessToken", ""),
                    "refresh_token": self.msrs_ms_token.get("refreshToken", ""),
                    "token_type": self.msrs_ms_token.get("tokenType", "Bearer"),
                    "expires_in": self.msrs_ms_token.get("expiresIn", 0),
                }
            else:
                logger.error(
                    f"Could not get token for client {self.msrs_auto_refresh_url}"
                )
        except Exception as e:
            logger.error(f"Error fetching token: {e}", exc_info=True)
            logger.warning(f"NOTE: {self}")
            raise e
        return self.msrs_oathlib_token

    def _token_saver(self, token):
        logger.debug("@@@ msrs: TOKEN SAVER SAVING:")
        logger.info(pprint.pformat(token))

    def verify_auth(self) -> typing.Tuple[bool, typing.Optional[str]]:
        try:
            if self.msrs_verification_url:
                logger.info(
                    "@@@ msrs: Verification URL specified, performing http verification"
                )
                res = self.get(self.msrs_verification_url)
                if res is None:
                    raise Exception("No response object returned")
                if not res:
                    res.raise_for_status()
                if self.msrs_verification_element:
                    logger.info(
                        "@@@ msrs: Verification element specified, performing json result verification"
                    )
                    if not res.text:
                        return False, "Respones was empty"
                    j = None
                    try:
                        j = res.json()
                    except ValueError:
                        return False, "No json in response"
                    if not j:
                        return False, "Json reponse was empty"
                    if not j.get(self.msrs_verification_element, False):
                        return (
                            False,
                            f"Expected json element '{self.msrs_verification_element}' not found in response",
                        )
                else:
                    logger.info(
                        f"@@@ msrs: No verification element specified, skipping json result verification"
                    )
            else:
                logger.info(
                    f"@@@ msrs: No verification URL specified, skipping http verification"
                )
        except requests.exceptions.HTTPError as e:
            return False, "Verification url could not be reached: {e}"
        except Exception as e:
            return False, f"Unexpected failure: {e}"
        # Success
        return True, None

    def prepare_request(self, request):
        logging.debug(
            f"@@@ msrs: prepare_request(method={request.method}, url='{request.url}')."
        )
        return super(MsRequestsSession, self).prepare_request(request)

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        client_id=None,
        client_secret=None,
        **kwargs,
    ):
        logging.info(f"@@@ msrs: request(method={method}, url='{url}').")
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

        if there's no auth header or it's empty -> use inherited from oauth2 functionality to add token on requests
        """
        logging.debug(f"@@@ msrs: send(method={request.method}, url='{request.url}').")
        try:
            if request.headers is not None and request.headers.get(
                self.msrs_aouth_header, False
            ):
                # send prepared Request if access token exists in the Request
                response = super().send(request, **kwargs)
            else:
                # make another call to get token into the header
                response = self.request(
                    method=request.method,
                    url=request.url,
                    data=request.body,
                    headers=request.headers,
                    **kwargs,
                )
            logging.debug(f"@@@ msrs: Response head follows: -----------------------")
            logging.info(response.content[0:200])
            return response
        except requests.exceptions.NewConnectionError as e:
            logger.error(
                f"Could not connect (method={request.method}, url='{request.url}'): {e}"
            )
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP STATUS CODE WAS: {e}")
        except Exception as e:
            logger.error(
                f"Could not perform request(method={request.method}, url='{request.url}'): {e}",
                exc_info=True,
            )
        raise e

    def close(self):
        logging.debug(f"@@@ msrs: close().")
        return super(MsRequestsSession, self).close()

    def __repr__(self):
        return f"""{self.__class__.__name__}: {{
    type:                 '{'ADAL' if self.msrs_do_adal else 'MSAL'}',
    client_id:            '{self.msrs_client_id}',
    resource_uri:         '{self.msrs_resource_uri}',
    client_secret:        'hidden',
    tenant:               '{self.msrs_tenant}',
    validate_authority:   '{self.msrs_validate_authority}',
    authority_host_url:   '{self.msrs_authority_host_url}',
    auto_refresh_url:     '{self.msrs_auto_refresh_url}',
    verification_url:     '{self.msrs_verification_url}',
    verification_element: '{self.msrs_verification_element}'
}}
"""
