from abc import ABC, abstractproperty, abstractmethod


class WalletManagerInterface(ABC):
    @abstractproperty
    def wallet(self):
        pass

    @abstractproperty
    def tx_storage(self):
        pass

    @abstractmethod
    def timestamp_now(self):
        pass

    @abstractmethod
    def get_new_tx_parents(self, timestamp=None):
        """Select which transactions will be confirmed by a new transaction.

        :return: The hashes of the parents for a new transaction.
        :rtype: List[bytes(hash)]
        """
        pass

    @abstractmethod
    def minimum_tx_weight(self, tx):
        """Returns the minimum weight for the param tx.

        The minimum is calculated by the following function:

        w = log(size, 2) + log(amount, 2) + 0.5

        :param tx: tx to calculate the minimum weight
        :type tx: :py:class:`hathor.transaction.transaction.Transaction`

        :return: minimum weight for the tx
        :rtype: float
        """
        pass

    @abstractmethod
    def propagate_tx(self, tx):
        """Push a new transaction to the network. It is used by both the wallet and the mining modules.

        :return: True if the transaction was accepted
        :rtype: bool
        """
        pass


class WalletManager(WalletManagerInterface):
    """This class is used to restrict what the wallet can use from the manager so it's easier to define an interface"""

    def __init__(self, wallet, tx_storage_readonly, manager_wallet_api, *, reactor):
        self._wallet = wallet
        self._tx_storage = tx_storage_readonly
        self._manager = manager_wallet_api
        self._reactor = reactor

    @classmethod
    def from_hathor_manager(cls, manager):
        return cls(manager.wallet, manager.tx_storage, manager, reactor=manager.reactor)

    @property
    def wallet(self):
        return self._wallet

    @property
    def tx_storage(self):
        return self._tx_storage

    def timestamp_now(self):
        return int(self._reactor.seconds())

    def get_new_tx_parents(self, timestamp=None):
        return self._manager.get_new_tx_parents(timestamp)

    def minimum_tx_weight(self, tx):
        return self._manager.minimum_tx_weight(tx)

    def propagate_tx(self, tx):
        return self._manager.propagate_tx(tx)
