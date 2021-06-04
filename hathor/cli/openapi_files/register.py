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
