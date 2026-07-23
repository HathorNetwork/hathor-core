# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.sysctl.exception import SysctlException
from hathor.sysctl.sysctl import Sysctl
from hathor.websocket.factory import HathorAdminWebsocketFactory


class WebsocketManagerSysctl(Sysctl):
    def __init__(self, factory: HathorAdminWebsocketFactory) -> None:
        super().__init__()
        self.factory = factory

        self.register(
            'max_subs_addrs_conn',
            self.get_max_subs_addrs_conn,
            self.set_max_subs_addrs_conn,
        )
        self.register(
            'max_subs_addrs_empty',
            self.get_max_subs_addrs_empty,
            self.set_max_subs_addrs_empty,
        )

    def get_max_subs_addrs_conn(self) -> int:
        """Return the maximum number of subscribed addresses per websocket connection.
        Note: -1 means unlimited"""
        value = self.factory.max_subs_addrs_conn
        if value is None:
            return -1
        return value

    def set_max_subs_addrs_conn(self, value: int) -> None:
        """Change the maximum number of subscribed addresses per websocket connection.
        Use -1 for unlimited"""
        if value == -1:
            self.factory.max_subs_addrs_conn = None
            return
        if value < 0:
            raise SysctlException('value must be >= 0 or -1')
        self.factory.max_subs_addrs_conn = value

    def get_max_subs_addrs_empty(self) -> int:
        """Return the maximum number of subscribed addresses that do not have any outputs per websocket connection.
        Note: -1 means unlimited"""
        value = self.factory.max_subs_addrs_empty
        if value is None:
            return -1
        return value

    def set_max_subs_addrs_empty(self, value: int) -> None:
        """Change the maximum number of subscribed addresses that do not have any outputs per websocket connection.
        Use -1 for unlimited"""
        if value == -1:
            self.factory.max_subs_addrs_empty = None
            return
        if value < 0:
            raise SysctlException('value must be >= 0 or -1')
        self.factory.max_subs_addrs_empty = value
