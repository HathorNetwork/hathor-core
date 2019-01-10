from abc import ABC, abstractmethod
from typing import Callable, Dict

from hathor.p2p.messages import ProtocolMessages
from hathor.transaction import BaseTransaction


class Plugin(ABC):
    @abstractmethod
    def start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_cmd_dict(self) -> Dict[ProtocolMessages, Callable]:
        raise NotImplementedError

    @abstractmethod
    def send_tx_to_peer_if_possible(self, tx: BaseTransaction) -> None:
        raise NotImplementedError
