"""
Storage Manager - Handles contract and state storage for the IDE
"""
import structlog
from hathor.nanocontracts.types import TokenUid
from hathor.nanocontracts.storage.contract_storage import Balance
import sys
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import json
import asyncio
from datetime import datetime

# Add the parent directory to Python path to import hathor modules
hathor_path = Path(__file__).parent.parent.parent.parent / "hathor"
sys.path.insert(0, str(hathor_path.parent))

# Import Hathor storage modules directly


logger = structlog.get_logger()


@dataclass
class ContractInfo:
    """Contract information for storage"""
    contract_id: str
    blueprint_id: str
    code: str
    methods: List[str]
    created_at: str
    state: Dict[str, Any] = None


@dataclass
class StorageInfo:
    """Storage information"""
    type: str
    contracts_count: int
    total_size: int


class MemoryStorage:
    """In-memory storage implementation for IDE"""

    def __init__(self):
        self.contracts: Dict[str, ContractInfo] = {}
        # contract_id -> token_uid -> balance
        self.balances: Dict[str, Dict[str, Balance]] = {}
        self.state: Dict[str, Dict[str, Any]] = {}  # contract_id -> state

    async def store_contract(self, contract_info: ContractInfo):
        """Store contract information"""
        self.contracts[contract_info.contract_id] = contract_info

        # Initialize empty balances and state
        if contract_info.contract_id not in self.balances:
            self.balances[contract_info.contract_id] = {}
        if contract_info.contract_id not in self.state:
            self.state[contract_info.contract_id] = {}

    async def get_contract(self, contract_id: str) -> Optional[ContractInfo]:
        """Get contract information"""
        return self.contracts.get(contract_id)

    async def list_contracts(self) -> List[ContractInfo]:
        """List all contracts"""
        return list(self.contracts.values())

    async def delete_contract(self, contract_id: str) -> bool:
        """Delete a contract"""
        if contract_id in self.contracts:
            del self.contracts[contract_id]
            self.balances.pop(contract_id, None)
            self.state.pop(contract_id, None)
            return True
        return False

    async def get_contract_balances(self, contract_id: str) -> Dict[str, Dict[str, Any]]:
        """Get all balances for a contract"""
        balances = self.balances.get(contract_id, {})
        return {
            token_uid: {
                "value": balance.value,
                "can_mint": balance.can_mint,
                "can_melt": balance.can_melt
            }
            for token_uid, balance in balances.items()
        }

    async def get_contract_balance(self, contract_id: str, token_uid: str) -> Dict[str, Any]:
        """Get balance for specific contract and token"""
        balances = self.balances.get(contract_id, {})
        balance = balances.get(token_uid, Balance(
            value=0, can_mint=False, can_melt=False))

        return {
            "value": balance.value,
            "can_mint": balance.can_mint,
            "can_melt": balance.can_melt
        }

    async def set_contract_balance(
        self,
        contract_id: str,
        token_uid: str,
        value: int,
        can_mint: bool = False,
        can_melt: bool = False
    ) -> bool:
        """Set balance for testing purposes"""
        if contract_id not in self.balances:
            self.balances[contract_id] = {}

        self.balances[contract_id][token_uid] = Balance(
            value=value,
            can_mint=can_mint,
            can_melt=can_melt
        )
        return True

    async def get_contract_state(self, contract_id: str) -> Dict[str, Any]:
        """Get contract state"""
        return self.state.get(contract_id, {})

    async def set_contract_state(self, contract_id: str, state: Dict[str, Any]):
        """Set contract state"""
        self.state[contract_id] = state

    async def reset(self):
        """Reset all storage"""
        self.contracts.clear()
        self.balances.clear()
        self.state.clear()

    async def get_info(self) -> StorageInfo:
        """Get storage information"""
        # Calculate approximate size
        total_size = 0
        for contract in self.contracts.values():
            total_size += len(contract.code)
            total_size += len(json.dumps(asdict(contract)))

        return StorageInfo(
            type="memory",
            contracts_count=len(self.contracts),
            total_size=total_size
        )


class StorageManager:
    """Main storage manager"""

    def __init__(self, storage_type: str = "memory"):
        self.storage_type = storage_type

        if storage_type == "memory":
            self.storage = MemoryStorage()
        else:
            # Could implement Redis storage here
            raise NotImplementedError(
                f"Storage type '{storage_type}' not implemented")

        logger.info("Storage manager initialized", type=storage_type)

    async def store_contract(
        self,
        contract_id: str,
        blueprint_id: str,
        code: str,
        methods: List[str] = None
    ) -> bool:
        """Store a new contract"""
        try:
            contract_info = ContractInfo(
                contract_id=contract_id,
                blueprint_id=blueprint_id,
                code=code,
                methods=methods or [],
                created_at=datetime.now().isoformat()
            )

            await self.storage.store_contract(contract_info)
            logger.info("Contract stored", contract_id=contract_id)
            return True

        except Exception as e:
            logger.error("Failed to store contract",
                         contract_id=contract_id, error=str(e))
            return False

    async def get_contract(self, contract_id: str) -> Optional[ContractInfo]:
        """Get contract information"""
        return await self.storage.get_contract(contract_id)

    async def list_contracts(self) -> List[ContractInfo]:
        """List all stored contracts"""
        return await self.storage.list_contracts()

    async def delete_contract(self, contract_id: str) -> bool:
        """Delete a contract"""
        return await self.storage.delete_contract(contract_id)

    async def get_contract_balances(self, contract_id: str) -> Dict[str, Any]:
        """Get contract balances"""
        return await self.storage.get_contract_balances(contract_id)

    async def get_contract_balance(self, contract_id: str, token_uid: str) -> Dict[str, Any]:
        """Get specific contract balance"""
        return await self.storage.get_contract_balance(contract_id, token_uid)

    async def set_contract_balance(
        self,
        contract_id: str,
        token_uid: str,
        value: int,
        can_mint: bool = False,
        can_melt: bool = False
    ) -> bool:
        """Set contract balance for testing"""
        return await self.storage.set_contract_balance(
            contract_id, token_uid, value, can_mint, can_melt
        )

    async def get_contract_state(self, contract_id: str) -> Dict[str, Any]:
        """Get contract state"""
        return await self.storage.get_contract_state(contract_id)

    async def set_contract_state(self, contract_id: str, state: Dict[str, Any]):
        """Set contract state"""
        await self.storage.set_contract_state(contract_id, state)

    async def reset(self):
        """Reset all storage"""
        await self.storage.reset()
        logger.info("Storage reset")

    async def get_info(self) -> StorageInfo:
        """Get storage information"""
        return await self.storage.get_info()
