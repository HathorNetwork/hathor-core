#  Copyright 2024 Hathor Labs
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

from abc import abstractmethod
from collections.abc import Mapping, Sequence
from typing import AnyStr, Protocol

from twisted.internet.interfaces import IProcessProtocol, IProcessTransport, IReactorProcess
from zope.interface import implementer


@implementer(IReactorProcess)
class ReactorProcessProtocol(Protocol):
    """
    A Python protocol that stubs Twisted's IReactorProcess interface.
    """

    @abstractmethod
    def spawnProcess(
        self,
        processProtocol: IProcessProtocol,
        executable: bytes | str,
        args: Sequence[bytes | str],
        env: Mapping[AnyStr, AnyStr] | None = None,
        path: bytes | str | None = None,
        uid: int | None = None,
        gid: int | None = None,
        usePTY: bool = False,
        childFDs: Mapping[int, int | str] | None = None,
    ) -> IProcessTransport:
        raise NotImplementedError
