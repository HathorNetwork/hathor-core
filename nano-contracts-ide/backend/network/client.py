"""
Hathor Network Client - Integration with Hathor network
"""
import structlog
import sys
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path
import requests
import asyncio

# Add the parent directory to Python path to import hathor modules
hathor_path = Path(__file__).parent.parent.parent.parent / "hathor"
sys.path.insert(0, str(hathor_path.parent))


logger = structlog.get_logger()


@dataclass
class NetworkInfo:
    """Network information"""
    network: str
    node_url: Optional[str]
    connected: bool
    block_height: Optional[int]
    peer_count: Optional[int]


@dataclass
class DeployResult:
    """Contract deployment result"""
    tx_hash: str
    blueprint_id: str


class HathorClient:
    """Client for Hathor network integration"""

    def __init__(self, node_url: Optional[str] = None, network: str = "testnet"):
        self.node_url = node_url or self._get_default_node_url(network)
        self.network = network
        self.session = requests.Session()

        # Set default headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'NanoContractsIDE/1.0'
        })

        logger.info("Hathor client initialized",
                    network=network, url=self.node_url)

    def _get_default_node_url(self, network: str) -> str:
        """Get default node URL for network"""
        if network == "mainnet":
            return "https://node1.mainnet.hathor.network"
        elif network == "testnet":
            return "https://node1.testnet.hathor.network"
        else:  # localnet
            return "http://localhost:8080"

    async def get_network_info(self) -> NetworkInfo:
        """Get network connection information"""
        try:
            # Try to get node status
            response = await self._make_request("GET", "/node_info")

            if response:
                return NetworkInfo(
                    network=self.network,
                    node_url=self.node_url,
                    connected=True,
                    block_height=response.get(
                        "latest_block", {}).get("height"),
                    peer_count=response.get("peer_count")
                )
            else:
                return NetworkInfo(
                    network=self.network,
                    node_url=self.node_url,
                    connected=False,
                    block_height=None,
                    peer_count=None
                )

        except Exception as e:
            logger.error("Failed to get network info", error=str(e))
            return NetworkInfo(
                network=self.network,
                node_url=self.node_url,
                connected=False,
                block_height=None,
                peer_count=None
            )

    async def deploy_contract(
        self,
        code: str,
        private_key: str,
        blueprint_name: str = "MyBlueprint"
    ) -> DeployResult:
        """Deploy contract to Hathor network"""
        try:
            logger.info("Deploying contract to network", code_length=len(code))

            # In a real implementation, this would:
            # 1. Create OnChainBlueprint transaction
            # 2. Sign with private key
            # 3. Submit to network
            # 4. Return transaction hash and blueprint ID

            # For now, this is a mock implementation
            raise NotImplementedError(
                "Network deployment not yet implemented in IDE")

        except Exception as e:
            logger.error("Contract deployment failed", error=str(e))
            raise

    async def list_contracts(self) -> List[Dict[str, Any]]:
        """List contracts deployed on network"""
        try:
            # This would query the network for deployed nano contracts
            # For now, return empty list
            logger.info("Listing network contracts")
            return []

        except Exception as e:
            logger.error("Failed to list network contracts", error=str(e))
            return []

    async def get_contract_info(self, blueprint_id: str) -> Optional[Dict[str, Any]]:
        """Get contract information from network"""
        try:
            # Query network for contract info
            response = await self._make_request("GET", f"/nano_contracts/{blueprint_id}")
            return response

        except Exception as e:
            logger.error("Failed to get contract info",
                         blueprint_id=blueprint_id, error=str(e))
            return None

    async def call_contract_method(
        self,
        contract_id: str,
        method_name: str,
        args: List[Any] = None,
        actions: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Call contract method on network"""
        try:
            payload = {
                "contract_id": contract_id,
                "method": method_name,
                "args": args or [],
                "actions": actions or []
            }

            response = await self._make_request("POST", "/nano_contracts/call", data=payload)
            return response or {}

        except Exception as e:
            logger.error("Failed to call contract method", error=str(e))
            return {"error": str(e)}

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        timeout: int = 30
    ) -> Optional[Dict[str, Any]]:
        """Make HTTP request to Hathor node"""
        try:
            url = f"{self.node_url}{endpoint}"

            # Use asyncio to run the synchronous request
            loop = asyncio.get_event_loop()

            if method == "GET":
                response = await loop.run_in_executor(
                    None,
                    lambda: self.session.get(url, timeout=timeout)
                )
            else:
                response = await loop.run_in_executor(
                    None,
                    lambda: self.session.post(url, json=data, timeout=timeout)
                )

            if response.status_code == 200:
                return response.json()
            else:
                logger.warning("HTTP request failed",
                               status=response.status_code,
                               url=url)
                return None

        except requests.exceptions.RequestException as e:
            logger.warning("Network request failed", url=url, error=str(e))
            return None
        except Exception as e:
            logger.error("Request error", url=url, error=str(e))
            return None
