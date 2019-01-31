
from typing import Optional

import requests


def discover_hostname() -> Optional[str]:
    """ Try to discover your hostname. It is a synchonous operation and
    should not be called from twisted main loop.
    """
    return discover_ip_ipify()


def discover_ip_ipify() -> Optional[str]:
    """ Try to discover your IP address using ipify's api.
    It is a synchonous operation and should not be called from twisted main loop.
    """
    response = requests.get('https://api.ipify.org')
    if response.ok:
        # It may be either an ipv4 or ipv6 in string format.
        ip = response.text
        return ip
    return None
