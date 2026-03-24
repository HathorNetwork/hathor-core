# Copyright 2025 Hathor Labs
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

from __future__ import annotations

from collections.abc import Callable

from hathorlib.nanocontracts.types import NC_METHOD_TYPE_ATTR, NCMethodType


def is_nc_public_method(method: Callable) -> bool:
    """Return True if the method is nc_public."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) == NCMethodType.PUBLIC


def is_nc_view_method(method: Callable) -> bool:
    """Return True if the method is nc_view."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) == NCMethodType.VIEW


def is_nc_fallback_method(method: Callable) -> bool:
    """Return True if the method is nc_fallback."""
    return getattr(method, NC_METHOD_TYPE_ATTR, None) == NCMethodType.FALLBACK
