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
