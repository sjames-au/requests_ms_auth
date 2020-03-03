import adal
import msal
import logging
import oauthlib.oauth2
import pprint
import requests
import requests_oauthlib
import typing

logger = logging.getLogger(__name__)


class MsRequestsSession(requests_oauthlib.OAuth2Session):

    """
    A wrapper for OAuth2Session that also implements adal token fetch.
    See https://requests.readthedocs.io/en/latest/_modules/requests/sessions/#Session
    See https://requests-oauthlib.readthedocs.io/en/latest/api.html#oauth-2-0-session
    See https://adal-python.readthedocs.io/en/latest/
    """

    def __init__(self, auth_config):
        self._set_config(auth_config)
        self.raa_state = None
        self.raa_token = self._fetch_access_token()
        if not self.raa_token:
            raise Exception("Could not generate token")
        # client=requests_oauthlib.WebApplicationClient(client_id=self.raa_client_id, token=self.raa_token)
        self.raa_client = oauthlib.oauth2.BackendApplicationClient(
            client_id=self.raa_client_id,
            token=self.raa_token,
            auto_refresh_url=self.raa_auto_refresh_url,
            auto_refresh_kwargs=self.raa_auto_refresh_kwargs,
            token_updater=self._token_saver,
            scope=self.raa_scope,
        )
        logging.debug(
            f"@@@ raa Session: __init__(client_id={self.raa_client_id}, auto_refresh_url={self.raa_auto_refresh_url}, scope={self.raa_scope})."
        )
        super(MsRequestsSession, self).__init__(
            client=self.raa_client, token=self.raa_token
        )
        self.verify_auth()

    def _set_config(self, auth_config):
        self.raa_auth_config = auth_config
        self.raa_client_id = self.raa_auth_config.get("client_id")
        self.raa_do_adal = self.raa_auth_config.get("do_adal", False)
        if not self.raa_client_id:
            raise Exception("No client_id specified")
        self.raa_client_secret = self.raa_auth_config.get("client_secret")
        if not self.raa_client_secret:
            raise Exception("No client_secret specified")
        self.raa_resource_uri = self.raa_auth_config.get(
            "resource", "https://management.core.windows.net/"
        )
        if not self.raa_resource_uri:
            raise Exception("No resource_uri specified")
        self.raa_authority_host_url = self.raa_auth_config.get(
            "authority_host_url", "https://login.microsoftonline.com"
        )
        if not self.raa_authority_host_url:
            raise Exception("No authority_host_url specified")
        self.raa_tenant = self.raa_auth_config.get("tenant", "adfs")
        if not self.raa_tenant:
            raise Exception("No tenant specified")
        self.raa_validate_authority = self.raa_tenant != "adfs"
        self.raa_scope = self.raa_auth_config.get("scope", ["read", "write"])
        self.raa_verification_url = self.raa_auth_config.get("verification_url")
        if not self.raa_verification_url:
            raise Exception("No verification_url specified")
        self.raa_auto_refresh_url = f"{self.raa_authority_host_url}/{self.raa_tenant}"
        self.raa_auto_refresh_kwargs = {
            "client_id": self.raa_client_id,
            "client_secret": self.raa_client_secret,
            "resource": self.raa_resource_uri,
        }  # aka extra

    def _fetch_access_token(self):
        if self.raa_do_adal:
            logger.info("NOTE: Doing ADAL")
            self._fetch_access_token_adal()
        else:
            logger.info("NOTE: Doing MSAL")
            self._fetch_access_token_msal()

    def _fetch_access_token_msal(self):
        self.raa_adal_token = None
        self.raa_oathlib_token = None
        try:
            context = msal.ConfidentialClientApplication(
                authority=self.raa_auto_refresh_url,
                validate_authority=self.raa_validate_authority,
                api_version=None,
                client_id=self.raa_client_id,
                client_credential=self.raa_client_secret,
            )
            self.raa_adal_token = (
                context.acquire_token_for_client(scopes=[self.raa_resource_uri]) or {}
            )
            if self.raa_adal_token:
                self.raa_oathlib_token = {
                    "access_token": self.raa_adal_token.get("accessToken", ""),
                    "refresh_token": self.raa_adal_token.get("refreshToken", ""),
                    "token_type": self.raa_adal_token.get("tokenType", "Bearer"),
                    "expires_in": self.raa_adal_token.get("expiresIn", 0),
                }
            else:
                logger.error(
                    f"Could not get token for client {self.raa_auto_refresh_url}"
                )
        except Exception as e:
            logger.error(f"Error fetching token: {e}", exc_info=True)
            logger.warning(
                "NOTE:\n"
                + f"client_id:            {self.raa_client_id}\n"
                + f"client_secret:        [hidden]\n"
                + f"tenant:               {self.raa_tenant}\n"
                + f"validate_authority:   {self.raa_validate_authority}\n"
                + f"authority_host_url:   {self.raa_authority_host_url}\n"
                + f"auto_refresh_url:     {self.raa_auto_refresh_url}\n"
            )
            raise e
        return self.raa_oathlib_token

    def _fetch_access_token_adal(self):
        self.raa_adal_token = None
        self.raa_oathlib_token = None
        try:
            context = adal.AuthenticationContext(
                authority=self.raa_auto_refresh_url,
                validate_authority=self.raa_validate_authority,
                api_version=None,
            )
            self.raa_adal_token = (
                context.acquire_token_with_client_credentials(
                    self.raa_resource_uri, self.raa_client_id, self.raa_client_secret
                )
                or {}
            )
            if self.raa_adal_token:
                self.raa_oathlib_token = {
                    "access_token": self.raa_adal_token.get("accessToken", ""),
                    "refresh_token": self.raa_adal_token.get("refreshToken", ""),
                    "token_type": self.raa_adal_token.get("tokenType", "Bearer"),
                    "expires_in": self.raa_adal_token.get("expiresIn", 0),
                }
            else:
                logger.error(
                    f"Could not get token for client {self.raa_auto_refresh_url}"
                )
        except Exception as e:
            logger.error(f"Error fetching token: {e}", exc_info=True)
            logger.warning(
                "NOTE:\n"
                + f"client_id:            {self.raa_client_id}\n"
                + f"client_secret:        [hidden]\n"
                + f"tenant:               {self.raa_tenant}\n"
                + f"validate_authority:   {self.raa_validate_authority}\n"
                + f"authority_host_url:   {self.raa_authority_host_url}\n"
                + f"auto_refresh_url:     {self.raa_auto_refresh_url}\n"
            )
            raise e
        return self.raa_oathlib_token

    def _token_saver(self, token):
        logger.debug("@@@ raa Session: TOKEN SAVER SAVING:")
        logger.info(pprint.pformat(token))
        pass

    def verify_auth(self) -> typing.Tuple[bool, typing.Optional[str]]:
        try:
            url = self.raa_auth_config.get("verification_url")
            if url:
                logger.debug(
                    "@@@ raa Session: Verification URL specified, performing verification"
                )
                res = self.get(url)
                if res is None:
                    raise Exception("No response object returned")
                if not res:
                    res.raise_for_status()
            else:
                logger.debug(
                    f"@@@ raa Session: No verification URL specified in {pprint.pformat(self.raa_auth_config)}, skipping verification"
                )
        except Exception as e:
            # Failure
            raise e
            return False, f"{e}"
        # Success
        return True, None

    def prepare_request(self, request):
        logging.debug(
            f"@@@ raa Session: prepare_request(method={request.method}, url='{request.url}')."
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
        logging.info(f"@@@ raa Session: request(method={method}, url='{url}').")
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
        logging.debug(
            f"@@@ raa Session: send(method={request.method}, url='{request.url}')."
        )
        try:
            response = super(MsRequestsSession, self).send(request, **kwargs)
            logging.debug(
                f"@@@ raa Session: Response head follows: -----------------------"
            )
            logging.info(response.content[0:200])
            return response
        except requests.exceptions.NewConnectionError as nce:
            logger.error(
                f"Could not connect (method={request.method}, url='{request.url}'): {nce}"
            )
        except requests.exceptions.HTTPError as he:
            logger.error(f"HTTP STATUS CODE WAS: {he}")
        except Exception as e:
            logger.error(
                f"Could not perform request(method={request.method}, url='{request.url}'): {e}",
                exc_info=True,
            )
        return None

    def close(self):
        logging.debug(f"@@@ raa Session: close().")
        return super(MsRequestsSession, self).close()
