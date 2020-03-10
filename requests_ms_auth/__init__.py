import pkg_resources
import os
from .session import MsRequestsSession

__all__ = ["MsRequestsSession"]

__version__ = "0.0.0"

rmsa_path: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
rmsa_version_file = f"{rmsa_path}/VERSION"

if pkg_resources.resource_exists(__name__, "VERSION"):
    __version__ = (
        pkg_resources.resource_string(__name__, "VERSION").decode("utf-8").strip()
    )
elif os.path.exists(rmsa_version_file):
    __version__ = read_file(rmsa_version_file)
else:
    # logger.warning("No version found")
    pass
