from .idor import IDORCheck
from .xss import XSSCheck
from .sqli import SQLiCheck
from .ssrf import SSRFCheck
from .auth import AuthCheck
from .open_redirect import OpenRedirectCheck
from .cors import CORSCheck
from .info_disclosure import InfoDisclosureCheck
from .rate_limit import RateLimitCheck
from .path_traversal import PathTraversalCheck
from .xxe import XXECheck

ALL_CHECKS = [
    IDORCheck,
    XSSCheck,
    SQLiCheck,
    SSRFCheck,
    AuthCheck,
    OpenRedirectCheck,
    CORSCheck,
    InfoDisclosureCheck,
    RateLimitCheck,
    PathTraversalCheck,
    XXECheck,
]
