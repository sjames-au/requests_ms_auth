import pkg_resources
import os
from .ms_session import MsRequestsSession
from .ms_session_config import MsSessionConfig

__version__ = "0.0.0"

rmsa_path: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
rmsa_version_file = f"{rmsa_path}/VERSION"


def _read_file(fname, strip=True):
    fn = os.path.join(os.path.dirname(os.path.abspath(__file__)), fname)
    data = ""
    if os.path.exists(fn):
        with open(fn) as f:
            data = f.read()
            data = data.strip() if strip else data
    return data


if pkg_resources.resource_exists(__name__, "VERSION"):
    __version__ = pkg_resources.resource_string(__name__, "VERSION").decode("utf-8").strip()
elif os.path.exists(rmsa_version_file):
    __version__ = _read_file(rmsa_version_file)
else:
    # logger.warning("No version found")
    pass

__all__ = ["MsRequestsSession", "MsSessionConfig", "__version__"]
