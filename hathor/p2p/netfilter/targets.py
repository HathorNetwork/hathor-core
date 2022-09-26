# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from hathor.p2p.netfilter.context import NetfilterContext
    from hathor.p2p.netfilter.rule import NetfilterRule


class NetfilterTarget:
    terminate: bool

    def to_json(self) -> Dict[str, Any]:
        return {
            'type': type(self).__name__,
            'target_params': {}
        }

    def execute(self, rule: 'NetfilterRule', context: 'NetfilterContext') -> None:
        pass


class NetfilterAccept(NetfilterTarget):
    terminate = True

    def __bool__(self):
        return True


class NetfilterReject(NetfilterTarget):
    terminate = True

    def __bool__(self):
        return False


class NetfilterJump(NetfilterTarget):
    terminate = False


class NetfilterLog(NetfilterTarget):
    terminate = False

    def __init__(self, msg: str) -> None:
        self.msg = msg

    def to_json(self) -> Dict[str, Any]:
        data = super().to_json()
        data['target_params']['msg'] = self.msg
        return data

    def execute(self, rule: 'NetfilterRule', context: 'NetfilterContext') -> None:
        print(self.msg.format(rule=rule, context=context))
