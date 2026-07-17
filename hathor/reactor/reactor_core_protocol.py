# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Callable, Optional, Protocol, Sequence

from twisted.internet.interfaces import IReactorCore
from zope.interface import implementer

if TYPE_CHECKING:
    from twisted.internet.defer import Deferred


@implementer(IReactorCore)
class ReactorCoreProtocol(Protocol):
    """
    A Python protocol that stubs Twisted's IReactorCore interface.
    """

    running: bool

    @abstractmethod
    def resolve(self, name: str, timeout: Sequence[int]) -> 'Deferred[str]':
        raise NotImplementedError

    @abstractmethod
    def run(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def crash(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def iterate(self, delay: float) -> None:
        raise NotImplementedError

    @abstractmethod
    def fireSystemEvent(self, eventType: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def addSystemEventTrigger(
        self,
        phase: str,
        eventType: str,
        callable: Callable[..., Any],
        *args: object,
        **kwargs: object,
    ) -> Any:
        raise NotImplementedError

    @abstractmethod
    def removeSystemEventTrigger(self, triggerID: Any) -> None:
        raise NotImplementedError

    @abstractmethod
    def callWhenRunning(self, callable: Callable[..., Any], *args: object, **kwargs: object) -> Optional[Any]:
        raise NotImplementedError
