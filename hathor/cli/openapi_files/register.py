from typing import List

from twisted.web.resource import Resource

_registered_resources = []


def register_resource(resource_class: Resource) -> Resource:
    """ Register a resource class to be added in the openapi docs page
    """
    global _registered_resources
    _registered_resources.append(resource_class)
    return resource_class


def get_registered_resources() -> List[Resource]:
    """ Returns a list with all the resources registered for the docs
    """
    from hathor.p2p.resources import __all__  # noqa: 401
    from hathor.resources import ProfilerResource  # noqa: 401
    from hathor.stratum.resources import MiningStatsResource  # noqa: 401
    from hathor.transaction.resources import __all__  # noqa: 401
    from hathor.version_resource import VersionResource  # noqa: 401
    from hathor.wallet.resources.nano_contracts import __all__  # noqa: 401
    from hathor.wallet.resources.thin_wallet import __all__  # noqa: 401
    from hathor.websocket import WebsocketStatsResource  # noqa: 401
    global _registered_resources
    return _registered_resources
