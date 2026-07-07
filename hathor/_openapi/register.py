# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TypeVar

from hathor.api_util import Resource  # skip-cli-import-custom-check

_registered_resources: list[type[Resource]] = []


# XXX: this type var is used to indicate that the returned class is the same as the input class
ResourceClass = TypeVar('ResourceClass', bound=type[Resource])


def register_resource(resource_class: ResourceClass) -> ResourceClass:
    """ Register a resource class to be added in the openapi docs page
    """
    global _registered_resources
    _registered_resources.append(resource_class)
    return resource_class


def get_registered_resources() -> list[type[Resource]]:
    """ Returns a list with all the resources registered for the docs
    """
    import hathor.event.resources.event
    import hathor.feature_activation.resources.feature
    import hathor.healthcheck.resources.healthcheck
    import hathor.nanocontracts.resources
    import hathor.p2p.resources
    import hathor.profiler.resources
    import hathor.stratum.resources
    import hathor.transaction.resources
    import hathor.version_resource
    import hathor.wallet.resources.nano_contracts
    import hathor.wallet.resources.thin_wallet
    import hathor.websocket
    global _registered_resources
    return _registered_resources
