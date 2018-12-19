from twisted.web.resource import Resource

from hathor.wallet.resources import BalanceResource, HistoryResource, AddressResource, \
                                    SendTokensResource, UnlockWalletResource, \
                                    LockWalletResource, StateWalletResource, SignTxResource
from hathor.wallet.resources.nano_contracts import NanoContractMatchValueResource, NanoContractDecodeResource, \
                                                   NanoContractExecuteResource


class WalletResources(Resource):
    def __init__(self, wallet):
        super().__init__()
        contracts_resources = [
            (b'match-value', NanoContractMatchValueResource(wallet)),
            (b'decode', NanoContractDecodeResource(wallet)),
            (b'execute', NanoContractExecuteResource(wallet)),
        ]
        contracts_resource = Resource()
        for url_path, res in contracts_resources:
            contracts_resource.putChild(url_path, res)

        wallet_resources = [
            (b'balance', BalanceResource(wallet)),
            (b'history', HistoryResource(wallet)),
            (b'address', AddressResource(wallet)),
            (b'send_tokens', SendTokensResource(wallet)),
            (b'sign_tx', SignTxResource(wallet)),
            (b'unlock', UnlockWalletResource(wallet)),
            (b'lock', LockWalletResource(wallet)),
            (b'state', StateWalletResource(wallet)),
            (b'nano-contract', contracts_resource),
        ]
        for url_path, res in wallet_resources:
            self.putChild(url_path, res)
