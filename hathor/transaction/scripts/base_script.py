# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
