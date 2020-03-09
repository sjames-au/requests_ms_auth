"""Contain logic for Backend Client for using by Session"""
import logging
import time

import oauthlib.oauth2

logger = logging.getLogger(__name__)


class MsBackendApplicationClient(oauthlib.oauth2.BackendApplicationClient):
    """Inherits Client for session requests to add more functionality"""

    def is_access_token_expired(self) -> bool:
        """Check if 'access token' expired

        Note: expiration time will be speed up not to have overlap when token is invalid

        Returns:
            True: if token expired
            False: if token not expired
        """
        token_expiration_time_correction = 15  # in seconds

        if self._expires_at and (self._expires_at - token_expiration_time_correction) < time.time():
            logger.debug("Token has expired.")
            return True
        return False
