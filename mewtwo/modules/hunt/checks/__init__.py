from .idor import IDORCheck
from .xss import XSSCheck
from .sqli import SQLiCheck
from .ssrf import SSRFCheck
from .auth import AuthCheck
from .open_redirect import OpenRedirectCheck
from .cors import CORSCheck
from .info_disclosure import InfoDisclosureCheck

ALL_CHECKS = [
    IDORCheck,
    XSSCheck,
    SQLiCheck,
    SSRFCheck,
    AuthCheck,
    OpenRedirectCheck,
    CORSCheck,
    InfoDisclosureCheck,
]
