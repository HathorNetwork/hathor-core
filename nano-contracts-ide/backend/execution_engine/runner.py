"""
Nano Contracts Execution Engine - Direct integration with Hathor's nano contracts
"""
import structlog
from hathor.transaction.storage import TransactionStorage
from hathor.reactor import ReactorProtocol
from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint, Code, CodeKind
from hathor.nanocontracts.types import ContractId, BlueprintId, VertexId
from hathor.nanocontracts.storage.block_storage import NCBlockStorage
from hathor.nanocontracts.storage import NCMemoryStorageFactory
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.runner.runner import RunnerFactory
from hathor.nanocontracts import Context, Blueprint, NCFail
import sys
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import asyncio
from pathlib import Path

# Add the parent directory to Python path to import hathor modules
hathor_path = Path(__file__).parent.parent.parent.parent / "hathor"
sys.path.insert(0, str(hathor_path.parent))

# Import Hathor nano contracts modules directly


logger = structlog.get_logger()


@dataclass
class CompileResult:
    """Result of contract compilation"""
    success: bool
    blueprint_id: Optional[str] = None
    gas_estimate: Optional[int] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class ExecutionResult:
    """Result of contract execution"""
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    gas_used: Optional[int] = None
    logs: List[str] = field(default_factory=list)
    state_changes: Dict[str, Any] = field(default_factory=dict)


class MockReactor:
    """Mock reactor for testing purposes"""

    def __init__(self):
        self.clock = MockClock()

    def callLater(self, delay, func, *args, **kwargs):
        # For IDE purposes, we execute immediately
        return func(*args, **kwargs)

    def seconds(self):
        """Return current time in seconds (delegated to clock)"""
        return self.clock.seconds()


class MockClock:
    """Mock clock for testing"""

    def __init__(self):
        self._time = 0

    def seconds(self):
        return self._time

    def advance(self, amount):
        self._time += amount


# Global storage instances that persist across API calls
_global_blueprint_storage = {}
_global_storage_factory = None
_global_block_storage = None
_global_runner_instance = None
_global_runner_engines = {}


class MockTransactionStorage:
    """Mock transaction storage for IDE execution"""

    def __init__(self):
        # Use global storage instead of instance storage
        self._blueprints = _global_blueprint_storage

    def get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]:
        """Get blueprint class by ID"""
        if blueprint_id in self._blueprints:
            return self._blueprints[blueprint_id]
        raise ValueError(f"Blueprint {blueprint_id.hex()} not found")

    def store_blueprint(self, blueprint_id: BlueprintId, blueprint_class: type[Blueprint]):
        """Store blueprint class"""
        self._blueprints[blueprint_id] = blueprint_class
        logger.info(f"Stored blueprint {blueprint_id.hex()}, total blueprints: {len(self._blueprints)}")


class ContractRunner:
    """Main contract execution engine for the IDE"""

    def __init__(self):
        # Set environment variable for nano contracts enabled configuration
        import os
        from hathor.conf.settings import NanoContractsSetting

        # Set up environment to use our custom IDE configuration with nano contracts enabled
        ide_config_path = Path(__file__).parent.parent / 'ide_config.yml'
        os.environ['HATHOR_CONFIG_YAML'] = str(ide_config_path)

        # Initialize mock components
        self.reactor = MockReactor()
        self.settings = self._create_test_settings()
        self.tx_storage = MockTransactionStorage()

        # Use global storage to persist contract state across API calls
        global _global_storage_factory, _global_block_storage
        if _global_storage_factory is None:
            _global_storage_factory = NCMemoryStorageFactory()
            _global_block_storage = _global_storage_factory.get_empty_block_storage()
            logger.info("Initialized global contract storage")

        self.storage_factory = _global_storage_factory
        self.block_storage = _global_block_storage

        # Create runner factory
        self.runner_factory = RunnerFactory(
            reactor=self.reactor,
            settings=self.settings,
            tx_storage=self.tx_storage,
            nc_storage_factory=self.storage_factory
        )

        logger.info("Contract runner initialized")

    @classmethod
    def get_instance(cls):
        """Get singleton instance of ContractRunner"""
        global _global_runner_instance
        if _global_runner_instance is None:
            _global_runner_instance = cls()
            logger.info("Created singleton ContractRunner instance")
        return _global_runner_instance

    def _create_test_settings(self) -> HathorSettings:
        """Create test settings for IDE execution"""
        # Import the nano contracts setting enum
        from hathor.conf.settings import NanoContractsSetting

        # Use testnet-golf settings as base for IDE
        settings = HathorSettings(
            P2PKH_VERSION_BYTE=b'\x49',
            MULTISIG_VERSION_BYTE=b'\x87',
            NETWORK_NAME='ide-testnet',
            BOOTSTRAP_DNS=[],
            ENABLE_NANO_CONTRACTS=NanoContractsSetting.ENABLED,
            NC_INITIAL_FUEL_TO_CALL_METHOD=1000000,
            NC_MEMORY_LIMIT_TO_CALL_METHOD=100 * 1024 * 1024,  # 100MB
            NC_INITIAL_FUEL_TO_LOAD_BLUEPRINT_MODULE=100000,
            NC_MEMORY_LIMIT_TO_LOAD_BLUEPRINT_MODULE=50 * 1024 * 1024,  # 50MB
            NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_COMPRESSED=1024 * 1024,  # 1MB
            NC_ON_CHAIN_BLUEPRINT_CODE_MAX_SIZE_UNCOMPRESSED=10 * 1024 * 1024,  # 10MB
        )

        return settings

    async def compile_contract(self, code: str, blueprint_name: str = "MyBlueprint") -> CompileResult:
        """Compile a nano contract from source code"""
        try:
            logger.info("Compiling contract", code_length=len(code))

            # Create code object
            code_obj = Code.from_python_code(code, self.settings)

            # Create OnChainBlueprint
            blueprint = OnChainBlueprint(
                code=code_obj,
                storage=self.tx_storage
            )

            # Try to load and validate the blueprint
            try:
                blueprint_class = blueprint.get_blueprint_class()
                # Create a proper 32-byte blueprint ID
                import hashlib
                blueprint_input = b'test_blueprint_' + code.encode('utf-8')
                blueprint_hash = hashlib.sha256(blueprint_input).digest()
                blueprint_id = BlueprintId(VertexId(blueprint_hash))

                # Store the blueprint for later use
                self.tx_storage.store_blueprint(blueprint_id, blueprint_class)

                return CompileResult(
                    success=True,
                    blueprint_id=blueprint_id.hex(),
                    gas_estimate=1000  # Mock gas estimate
                )

            except Exception as e:
                logger.error("Blueprint validation failed", error=str(e))
                return CompileResult(
                    success=False,
                    errors=[str(e)]
                )

        except Exception as e:
            logger.error("Contract compilation failed",
                         error=str(e), exc_info=True)
            return CompileResult(
                success=False,
                errors=[f"Compilation failed: {str(e)}"]
            )

    async def execute_method(
        self,
        contract_id: str,
        method_name: str,
        args: List[Any] = None,
        kwargs: Dict[str, Any] = None,
        actions: List[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        caller_address: Optional[str] = None,
        method_type: Optional[str] = None
    ) -> ExecutionResult:
        """Execute a contract method"""
        try:
            logger.info("Executing method",
                        contract_id=contract_id, method=method_name)

            args = args or []
            kwargs = kwargs or {}
            actions = actions or []

            # Get or create a persistent runner for this session
            # Use a fixed seed so all operations share the same state
            import hashlib
            session_key = "ide_session"  # Use same session for all operations

            global _global_runner_engines
            if session_key not in _global_runner_engines:
                seed_input = b'ide_session_seed'
                proper_seed = hashlib.sha256(seed_input).digest()
                _global_runner_engines[session_key] = self.runner_factory.create(
                    block_storage=self.block_storage,
                    seed=proper_seed
                )
                logger.info("Created persistent runner engine for IDE session")

            runner = _global_runner_engines[session_key]

            # Convert string contract_id to ContractId
            contract_id_obj = ContractId(VertexId(bytes.fromhex(contract_id)))

            # Create mock context with caller address simulation
            from hathor.nanocontracts.vertex_data import VertexData
            from hathor.transaction import Transaction
            import hashlib

            # Create a minimal transaction for context
            mock_tx = Transaction()

            # Use provided caller address or generate a default one
            if caller_address:
                # Convert hex string to bytes for the caller
                caller_hash = bytes.fromhex(caller_address)
            else:
                # Generate a default caller hash
                caller_input = b'default_caller_' + contract_id.encode('utf-8')
                caller_hash = hashlib.sha256(caller_input).digest()

            mock_tx.hash = caller_hash
            vertex_data = VertexData.create_from_vertex(mock_tx)

            ctx = Context(
                actions=[],  # Convert actions if needed
                vertex=vertex_data,
                # Use caller address as caller_id
                caller_id=ContractId(VertexId(caller_hash)),
                timestamp=int(self.reactor.clock.seconds())
            )

            # Execute the method
            try:
                if method_name == "initialize":
                    # For initialize, we need to create the contract first
                    # The contract_id passed in is actually the blueprint_id from compilation
                    blueprint_id_obj = BlueprintId(
                        VertexId(bytes.fromhex(contract_id)))

                    # Generate a new contract_id for this instance
                    import hashlib
                    contract_input = b'contract_instance_' + \
                        contract_id.encode('utf-8') + os.urandom(8)
                    contract_hash = hashlib.sha256(contract_input).digest()
                    new_contract_id = ContractId(VertexId(contract_hash))

                    logger.info(f"Creating contract with args: {args}")
                    # For create_contract, we need to pass the initialization arguments properly
                    try:
                        # create_contract signature: (contract_id, blueprint_id, ctx, *init_args)
                        result = runner.create_contract(
                            new_contract_id,
                            blueprint_id_obj,
                            ctx,
                            *args  # Pass initialization arguments
                        )
                        logger.info(
                            f"Success creating contract, result: {result}")
                    except Exception as e:
                        logger.error(f"Contract creation failed: {str(e)}", exc_info=True)
                        raise e
                else:
                    # Use provided method_type instead of auto-detection
                    is_view_method = method_type == 'view'
                    logger.info(f"Method {method_name} type from frontend: {method_type}, is_view_method: {is_view_method}")

                    if is_view_method:
                        # Call view method (don't pass ctx to view methods)
                        logger.info(f"Calling view method {method_name} with args: {args}")

                        # Convert hex string addresses to bytes for view methods
                        converted_args = []
                        for arg in args:
                            if isinstance(arg, str) and len(arg) == 64 and all(c in '0123456789abcdefABCDEF' for c in arg):
                                # This looks like a hex address, convert to bytes
                                converted_args.append(bytes.fromhex(arg))
                                logger.info(f"Converted hex string {arg} to bytes")
                            else:
                                converted_args.append(arg)

                        try:
                            result = runner.call_view_method(
                                contract_id_obj,
                                method_name,
                                *converted_args
                            )
                            logger.info(f"View method result: {result}")
                        except Exception as e:
                            logger.error(f"View method failed: {str(e)}", exc_info=True)
                            raise e
                    else:
                        # Call public method
                        logger.info(f"Calling public method {method_name} with args: {args}")

                        # Convert hex string addresses to bytes for public methods too
                        converted_args = []
                        for arg in args:
                            if isinstance(arg, str) and len(arg) == 64 and all(c in '0123456789abcdefABCDEF' for c in arg):
                                # This looks like a hex address, convert to bytes
                                converted_args.append(bytes.fromhex(arg))
                                logger.info(f"Converted hex string {arg} to bytes")
                            else:
                                converted_args.append(arg)

                        try:
                            result = runner.call_public_method(
                                contract_id_obj,
                                method_name,
                                ctx,
                                *converted_args
                            )
                            logger.info(f"Public method result: {result}")
                        except Exception as e:
                            logger.error(f"Public method failed: {str(e)}", exc_info=True)
                            raise e

                # For initialize method, return the contract ID that was created
                if method_name == "initialize":
                    return ExecutionResult(
                        success=True,
                        result={"contract_id": new_contract_id.hex(
                        ), "initialization_result": result},
                        gas_used=500,  # Mock gas usage
                        logs=[],
                        state_changes={}
                    )
                else:
                    return ExecutionResult(
                        success=True,
                        result=result,
                        gas_used=500,  # Mock gas usage
                        logs=[],
                        state_changes={}
                    )

            except NCFail as e:
                logger.warning(
                    "Contract execution failed with NCFail", error=str(e))
                return ExecutionResult(
                    success=False,
                    error=f"Contract execution failed: {str(e)}"
                )
            except Exception as e:
                logger.error("Contract execution failed",
                             error=str(e), exc_info=True)
                return ExecutionResult(
                    success=False,
                    error=f"Execution error: {str(e)}"
                )

        except Exception as e:
            logger.error("Method execution failed",
                         error=str(e), exc_info=True)
            return ExecutionResult(
                success=False,
                error=f"Failed to execute method: {str(e)}"
            )

    async def get_contract_methods(self, contract_id: str) -> List[Dict[str, Any]]:
        """Get available methods for a contract"""
        try:
            # This would need to be implemented based on stored contract info
            # For now, return mock methods
            return [
                {
                    "name": "initialize",
                    "type": "public",
                    "parameters": [],
                    "returns": "None"
                },
                {
                    "name": "get_balance",
                    "type": "view",
                    "parameters": [],
                    "returns": "int"
                }
            ]
        except Exception as e:
            logger.error("Failed to get contract methods",
                         error=str(e), exc_info=True)
            return []
