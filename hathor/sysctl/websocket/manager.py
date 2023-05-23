# Copyright 2023 Hathor Labs
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
