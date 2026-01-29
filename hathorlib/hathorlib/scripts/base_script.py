#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseScript(ABC):
    """
    This class holds common methods for different script types to help abstracting the script type.
    """

    @abstractmethod
    def to_human_readable(self) -> dict[str, Any]:
        """Return a nice dict for using on informational json APIs."""
        raise NotImplementedError

    @abstractmethod
    def get_type(self) -> str:
        """Get script type name"""
        raise NotImplementedError

    @abstractmethod
    def get_script(self) -> bytes:
        """Get or build script"""
        raise NotImplementedError

    @abstractmethod
    def get_address(self) -> str:
        """Get address for this script."""
        raise NotImplementedError

    @abstractmethod
    def get_timelock(self) -> Optional[int]:
        """Get timelock for this script, completely optional."""
        raise NotImplementedError
