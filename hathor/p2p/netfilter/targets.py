# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hathor.p2p.netfilter.context import NetfilterContext
    from hathor.p2p.netfilter.rule import NetfilterRule


class NetfilterTarget:
    terminate: bool

    def to_json(self) -> dict[str, Any]:
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

    def to_json(self) -> dict[str, Any]:
        data = super().to_json()
        data['target_params']['msg'] = self.msg
        return data

    def execute(self, rule: 'NetfilterRule', context: 'NetfilterContext') -> None:
        print(self.msg.format(rule=rule, context=context))
