# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Callable, Protocol, Sequence

from twisted.internet.interfaces import IReactorTime
from zope.interface import implementer

if TYPE_CHECKING:
    from twisted.internet.interfaces import IDelayedCall


@implementer(IReactorTime)
class ReactorTimeProtocol(Protocol):
    """
    A Python protocol that stubs Twisted's IReactorTime interface.
    """

    @abstractmethod
    def seconds(self) -> float:
        raise NotImplementedError

    @abstractmethod
    def callLater(self, delay: float, callable: Callable[..., Any], *args: object, **kwargs: object) -> 'IDelayedCall':
        raise NotImplementedError

    @abstractmethod
    def getDelayedCalls(self) -> Sequence['IDelayedCall']:
        raise NotImplementedError
