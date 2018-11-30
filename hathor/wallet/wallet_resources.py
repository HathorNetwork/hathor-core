from twisted.web import resource

from hathor.wallet.resources import BalanceResource, HistoryResource, AddressResource, \
                                    SendTokensResource, UnlockWalletResource, \
                                    LockWalletResource, StateWalletResource, SignTxResource
from hathor.wallet.resources.nano_contracts import NanoContractMatchValueResource, NanoContractDecodeResource, \
                                                   NanoContractExecuteResource


class WalletResources(resource.Resource):
    def __init__(self, wallet_manager):
        super().__init__()
        resources = [
            # /wallet
            (b'balance', BalanceResource(wallet_manager)),
            (b'history', HistoryResource(wallet_manager)),
            (b'address', AddressResource(wallet_manager)),
            (b'send_tokens', SendTokensResource(wallet_manager)),
            (b'sign_tx', SignTxResource(manager), wallet_resource),
            (b'unlock', UnlockWalletResource(wallet_manager)),
            (b'lock', LockWalletResource(wallet_manager)),
            (b'state', StateWalletResource(wallet_manager)),
            # /wallet/nano-contract
            (b'match-value', NanoContractMatchValueResource(manager), contracts_resource),
            (b'decode', NanoContractDecodeResource(manager), contracts_resource),
            (b'execute', NanoContractExecuteResource(manager), contracts_resource),
        ]
        for url_path, resource in resources:
            self.putChild(url_path, resource)
