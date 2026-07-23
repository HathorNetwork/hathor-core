# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Protocol

from hathor.reactor.reactor_core_protocol import ReactorCoreProtocol
from hathor.reactor.reactor_tcp_protocol import ReactorTCPProtocol
from hathor.reactor.reactor_time_protocol import ReactorTimeProtocol


class ReactorProtocol(
    ReactorCoreProtocol,
    ReactorTimeProtocol,
    ReactorTCPProtocol,
    Protocol,
):
    """
    A Python protocol that represents the intersection of Twisted's IReactorCore+IReactorTime+IReactorTCP interfaces.
    """
    pass
