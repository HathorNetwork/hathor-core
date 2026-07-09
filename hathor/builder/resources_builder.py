# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import os
import re
from typing import TYPE_CHECKING, Any, Optional

from autobahn.twisted.resource import WebSocketResource
from structlog import get_logger
from twisted.web import server
from twisted.web.resource import Resource

from hathor.api_util import APIVersion
from hathor.event.resources.event import EventResource
from hathor.exception import BuilderError
from hathor.feature_activation.feature_service import FeatureService
from hathor.nanocontracts.resources.builtin import BlueprintBuiltinResource
from hathor.nanocontracts.resources.nc_creation import NCCreationResource
from hathor.nanocontracts.resources.nc_exec_logs import NCExecLogsResource
from hathor.nanocontracts.resources.on_chain import BlueprintOnChainResource
from hathor.prometheus import PrometheusMetricsExporter

if TYPE_CHECKING:
    from hathor.event.websocket.factory import EventWebsocketFactory
    from hathor.manager import HathorManager
    from hathor_cli.run_node_args import RunNodeArgs

logger = get_logger()

PROMETHEUS_METRIC_RE = re.compile(r'[a-zA-Z_:][a-zA-Z0-9_:]*')


def is_prometheus_metric_name_valid(name: str) -> bool:
    """Whether a matric name is valid.

    See: https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels

    >>> is_prometheus_metric_name_valid('')
    False
    >>> is_prometheus_metric_name_valid('hathor_core:')
    True
    >>> is_prometheus_metric_name_valid("'hathor_core:'")
    False
    >>> is_prometheus_metric_name_valid('_hathor_core')
    True
    >>> is_prometheus_metric_name_valid('__hathor_core')
    False
    """
    if not PROMETHEUS_METRIC_RE.match(name):
        return False
    if name.startswith('__'):
        return False
    return True


class ResourcesBuilder:
    def __init__(
        self,
        manager: 'HathorManager',
        args: 'RunNodeArgs',
        event_ws_factory: Optional['EventWebsocketFactory'],
        feature_service: FeatureService
    ) -> None:
        self.log = logger.new()
        self.manager = manager
        self.event_ws_factory = event_ws_factory
        self.wallet = manager.wallet

        self._args = args
        self._built_status = False
        self._built_prometheus = False

        self._feature_service = feature_service

    def build(self) -> Optional[server.Site]:
        if self._args.prometheus:
            self.create_prometheus()
        if self._args.status:
            return self.create_resources()
        return None

    def create_prometheus(self) -> PrometheusMetricsExporter:
        prometheus_prefix = self._args.prometheus_prefix
        if self._args.prometheus_prefix and not is_prometheus_metric_name_valid(prometheus_prefix):
            raise BuilderError(f'Invalid prometheus prefix, must match {PROMETHEUS_METRIC_RE.pattern}, '
                               'but the value given is {repr(prometheus_prefix)}')

        kwargs: dict[str, Any] = {
            'metrics': self.manager.metrics,
            'metrics_prefix': prometheus_prefix,
        }

        if self._args.data:
            kwargs['path'] = os.path.join(self._args.data, 'prometheus')
        else:
            raise BuilderError('To run prometheus exporter you must have a data path')

        prometheus = PrometheusMetricsExporter(**kwargs)
        prometheus.start()

        self._built_prometheus = True
        return prometheus

    def create_resources(self) -> server.Site:
        from hathor.conf.get_settings import get_global_settings
        from hathor.debug_resources import (
            DebugCrashResource,
            DebugLogResource,
            DebugMessAroundResource,
            DebugPrintResource,
            DebugRaiseResource,
            DebugRejectResource,
        )
        from hathor.feature_activation.resources.feature import FeatureResource
        from hathor.healthcheck.resources import HealthcheckResource
        from hathor.mining.ws import MiningWebsocketFactory
        from hathor.p2p.resources import (
            AddPeersResource,
            HealthcheckReadinessResource,
            MiningInfoResource,
            MiningResource,
            NetfilterRuleResource,
            StatusResource,
        )
        from hathor.profiler import get_cpu_profiler
        from hathor.profiler.resources import CPUProfilerResource, ProfilerResource
        from hathor.transaction.resources import (
            BlockAtHeightResource,
            CreateTxResource,
            DashboardTransactionResource,
            DecodeTxResource,
            GetBlockTemplateResource,
            GraphvizFullResource,
            GraphvizNeighboursResource,
            MempoolResource,
            PushTxResource,
            SubmitBlockResource,
            TransactionAccWeightResource,
            TransactionResource,
            TxParentsResource,
            UtxoSearchResource,
            ValidateAddressResource,
        )
        from hathor.version_resource import VersionResource
        from hathor.wallet.resources import (
            AddressResource,
            BalanceResource,
            HistoryResource,
            LockWalletResource,
            SendTokensResource,
            SignTxResource,
            StateWalletResource,
            UnlockWalletResource,
        )
        from hathor.wallet.resources.nano_contracts import (
            NanoContractDecodeResource,
            NanoContractExecuteResource,
            NanoContractMatchValueResource,
        )
        from hathor.wallet.resources.thin_wallet import (
            AddressBalanceResource,
            AddressHistoryResource,
            AddressSearchResource,
            SendTokensResource as SendTokensThinResource,
            TokenHistoryResource,
            TokenResource,
        )
        from hathor.websocket import HathorAdminWebsocketFactory, WebsocketStatsResource

        settings = get_global_settings()
        cpu = get_cpu_profiler()

        # TODO get this from a file. How should we do with the factory?
        root_v1a = Resource()
        root_v2 = Resource()

        wallet_resource_v1a = Resource()
        wallet_resource_v2 = Resource()
        root_v1a.putChild(b'wallet', wallet_resource_v1a)
        root_v2.putChild(b'wallet', wallet_resource_v2)
        thin_wallet_resource_v1a = Resource()
        thin_wallet_resource_v2 = Resource()
        root_v1a.putChild(b'thin_wallet', thin_wallet_resource_v1a)
        root_v2.putChild(b'thin_wallet', thin_wallet_resource_v2)
        contracts_resource = Resource()
        wallet_resource_v1a.putChild(b'nano-contract', contracts_resource)
        p2p_resource = Resource()
        root_v1a.putChild(b'p2p', p2p_resource)
        graphviz = Resource()
        # XXX: reach the resource through /graphviz/ too, previously it was a leaf so this wasn't a problem
        graphviz.putChild(b'', graphviz)
        for fmt in ['dot', 'pdf', 'png', 'jpg']:
            bfmt = fmt.encode('ascii')
            graphviz.putChild(b'full.' + bfmt, GraphvizFullResource(self.manager, format=fmt))
            graphviz.putChild(b'neighbours.' + bfmt, GraphvizNeighboursResource(self.manager, format=fmt))

        resources = [
            (b'status', StatusResource(self.manager), root_v1a),
            (b'version', VersionResource(self.manager, self._feature_service), root_v1a),
            (b'create_tx', CreateTxResource(self.manager, APIVersion.V1A), root_v1a),
            (b'create_tx', CreateTxResource(self.manager, APIVersion.V2), root_v2),
            (b'decode_tx', DecodeTxResource(self.manager), root_v1a),
            (b'validate_address', ValidateAddressResource(self.manager), root_v1a),
            (b'push_tx',
                PushTxResource(self.manager, self._args.max_output_script_size, self._args.allow_non_standard_script),
                root_v1a),
            (b'graphviz', graphviz, root_v1a),
            (b'transaction', TransactionResource(self.manager, APIVersion.V1A), root_v1a),
            (b'transaction', TransactionResource(self.manager, APIVersion.V2), root_v2),
            (b'block_at_height', BlockAtHeightResource(self.manager), root_v1a),
            (b'transaction_acc_weight', TransactionAccWeightResource(self.manager), root_v1a),
            (b'dashboard_tx', DashboardTransactionResource(self.manager), root_v1a),
            (b'profiler', ProfilerResource(self.manager), root_v1a),
            (b'top', CPUProfilerResource(self.manager, cpu), root_v1a),
            (b'mempool', MempoolResource(self.manager), root_v1a),
            (b'health', HealthcheckResource(self.manager), root_v1a),
            # mining
            (b'mining', MiningResource(self.manager), root_v1a),
            (b'getmininginfo', MiningInfoResource(self.manager), root_v1a),
            (b'get_block_template', GetBlockTemplateResource(self.manager, settings), root_v1a),
            (b'submit_block', SubmitBlockResource(self.manager), root_v1a),
            (b'tx_parents', TxParentsResource(self.manager), root_v1a),
            # /thin_wallet
            (b'address_history', AddressHistoryResource(self.manager), thin_wallet_resource_v1a),
            (b'address_balance', AddressBalanceResource(self.manager, APIVersion.V1A), thin_wallet_resource_v1a),
            (b'address_balance', AddressBalanceResource(self.manager, APIVersion.V2), thin_wallet_resource_v2),
            (b'address_search', AddressSearchResource(self.manager), thin_wallet_resource_v1a),
            (b'send_tokens', SendTokensThinResource(self.manager), thin_wallet_resource_v1a),
            (b'token', TokenResource(self.manager, APIVersion.V1A), thin_wallet_resource_v1a),
            (b'token', TokenResource(self.manager, APIVersion.V2), thin_wallet_resource_v2),
            (b'token_history', TokenHistoryResource(self.manager), thin_wallet_resource_v1a),
            # /wallet/nano-contract
            (b'match-value', NanoContractMatchValueResource(self.manager), contracts_resource),
            (b'decode', NanoContractDecodeResource(self.manager), contracts_resource),
            (b'execute', NanoContractExecuteResource(self.manager), contracts_resource),
            # /p2p
            (b'peers', AddPeersResource(self.manager), p2p_resource),
            (b'netfilter', NetfilterRuleResource(self.manager), p2p_resource),
            (b'readiness', HealthcheckReadinessResource(self.manager), p2p_resource),
            # Feature Activation
            (
                b'feature',
                FeatureResource(
                    settings=settings,
                    feature_service=self._feature_service,
                    tx_storage=self.manager.tx_storage
                ),
                root_v1a
            )
        ]
        # XXX: only enable UTXO search API if the index is enabled
        if self._args.utxo_index:
            resources.extend([
                (b'utxo_search', UtxoSearchResource(self.manager, APIVersion.V1A), root_v1a),
                (b'utxo_search', UtxoSearchResource(self.manager, APIVersion.V2), root_v2),
            ])

        if settings.ENABLE_NANO_CONTRACTS:
            from hathor.nanocontracts.resources import (
                BlueprintInfoResource,
                BlueprintSourceCodeResource,
                NanoContractHistoryResource,
                NanoContractStateResource,
                NCDryRunResource,
            )
            nc_resource_v1a = Resource()
            nc_resource_v2 = Resource()
            root_v1a.putChild(b'nano_contract', nc_resource_v1a)
            root_v2.putChild(b'nano_contract', nc_resource_v2)

            blueprint_resource = Resource()
            nc_resource_v1a.putChild(b'blueprint', blueprint_resource)
            blueprint_resource.putChild(b'info', BlueprintInfoResource(self.manager))
            blueprint_resource.putChild(b'builtin', BlueprintBuiltinResource(self.manager))
            blueprint_resource.putChild(b'on_chain', BlueprintOnChainResource(self.manager))
            blueprint_resource.putChild(b'source', BlueprintSourceCodeResource(self.manager))
            nc_resource_v1a.putChild(b'history', NanoContractHistoryResource(self.manager))
            nc_resource_v1a.putChild(b'state', NanoContractStateResource(self.manager, APIVersion.V1A))
            nc_resource_v2.putChild(b'state', NanoContractStateResource(self.manager, APIVersion.V2))
            nc_resource_v1a.putChild(b'creation', NCCreationResource(self.manager))
            nc_resource_v1a.putChild(b'logs', NCExecLogsResource(self.manager))
            nc_resource_v1a.putChild(b'dry_run', NCDryRunResource(
                self.manager.tx_storage, self.manager.consensus_algorithm.block_executor
            ))

        if self._args.enable_debug_api:
            debug_resource = Resource()
            root_v1a.putChild(b'_debug', debug_resource)
            resources.extend([
                (b'log', DebugLogResource(), debug_resource),
                (b'raise', DebugRaiseResource(self.manager.reactor), debug_resource),
                (b'reject', DebugRejectResource(self.manager.reactor), debug_resource),
                (b'print', DebugPrintResource(), debug_resource),
            ])
        if self._args.enable_crash_api:
            crash_resource = Resource()
            root_v1a.putChild(b'_crash', crash_resource)
            resources.extend([
                (b'exit', DebugCrashResource(self.manager.reactor), crash_resource),
                (b'mess_around', DebugMessAroundResource(self.manager), crash_resource),
            ])

        for url_path, resource, parent in resources:
            parent.putChild(url_path, resource)

        if self.manager.stratum_factory is not None:
            from hathor.stratum.resources import MiningStatsResource
            root_v1a.putChild(b'miners', MiningStatsResource(self.manager))

        with_wallet_api = bool(self.wallet and self._args.wallet_enable_api)
        if with_wallet_api:
            wallet_resources = (
                # /wallet
                (b'balance', BalanceResource(self.manager, APIVersion.V1A), wallet_resource_v1a),
                (b'balance', BalanceResource(self.manager, APIVersion.V2), wallet_resource_v2),
                (b'history', HistoryResource(self.manager), wallet_resource_v1a),
                (b'address', AddressResource(self.manager), wallet_resource_v1a),
                (b'send_tokens', SendTokensResource(self.manager, settings, APIVersion.V1A), wallet_resource_v1a),
                (b'send_tokens', SendTokensResource(self.manager, settings, APIVersion.V2), wallet_resource_v2),
                (b'sign_tx', SignTxResource(self.manager), wallet_resource_v1a),
                (b'unlock', UnlockWalletResource(self.manager), wallet_resource_v1a),
                (b'lock', LockWalletResource(self.manager), wallet_resource_v1a),
                (b'state', StateWalletResource(self.manager), wallet_resource_v1a),
            )
            for url_path, resource, parent in wallet_resources:
                parent.putChild(url_path, resource)

        # Websocket resource
        ws_factory = HathorAdminWebsocketFactory(manager=self.manager,
                                                 metrics=self.manager.metrics,
                                                 address_index=self.manager.tx_storage.indexes.addresses)
        if self._args.disable_ws_history_streaming:
            ws_factory.disable_history_streaming()
        root_v1a.putChild(b'ws', WebSocketResource(ws_factory))

        mining_ws_factory: MiningWebsocketFactory | None = None
        if settings.CONSENSUS_ALGORITHM.is_pow():
            # Mining websocket resource
            mining_ws_factory = MiningWebsocketFactory(self.manager)
            root_v1a.putChild(b'mining_ws', WebSocketResource(mining_ws_factory))

        ws_factory.subscribe(self.manager.pubsub)

        # Event websocket resource
        if self._args.x_enable_event_queue or self._args.enable_event_queue:
            root_v1a.putChild(b'event_ws', WebSocketResource(self.event_ws_factory))
            root_v1a.putChild(b'event', EventResource(self.manager._event_manager))

        # Websocket stats resource
        root_v1a.putChild(b'websocket_stats', WebsocketStatsResource(ws_factory))

        real_root = Resource()
        real_root.putChild(APIVersion.V1A.encode('ascii'), root_v1a)
        real_root.putChild(APIVersion.V2.encode('ascii'), root_v2)

        from hathor.profiler.site import SiteProfiler
        status_server = SiteProfiler(real_root)
        self.log.info('with status', listen=self._args.status, with_wallet_api=with_wallet_api)

        # Set websocket factory in metrics. It'll be started when the manager is started.
        self.manager.websocket_factory = ws_factory
        self.manager.metrics.websocket_factory = ws_factory
        self.manager.metrics.mining_ws_factory = mining_ws_factory

        self._built_status = True
        return status_server
