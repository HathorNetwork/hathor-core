# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
    import hathor.event.resources.event  # noqa: 401
    import hathor.feature_activation.resources.feature  # noqa: 401
    import hathor.healthcheck.resources.healthcheck  # noqa: 401
    import hathor.nanocontracts.resources  # noqa: 401
    import hathor.p2p.resources  # noqa: 401
    import hathor.profiler.resources  # noqa: 401
    import hathor.stratum.resources  # noqa: 401
    import hathor.transaction.resources  # noqa: 401
    import hathor.version_resource  # noqa: 401
    import hathor.wallet.resources.nano_contracts  # noqa: 401
    import hathor.wallet.resources.thin_wallet  # noqa: 401
    import hathor.websocket  # noqa: 401
    global _registered_resources
    return _registered_resources
