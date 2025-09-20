"""
Network API router - handles Hathor network integration
"""
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

from network.client import HathorClient


logger = structlog.get_logger()
router = APIRouter()


class NetworkInfo(BaseModel):
    """Network information"""
    network: str
    node_url: Optional[str]
    connected: bool
    block_height: Optional[int]
    peer_count: Optional[int]


class DeployRequest(BaseModel):
    """Request to deploy contract to network"""
    code: str
    private_key: str  # In production, this should be handled securely
    blueprint_name: Optional[str] = "MyBlueprint"


class DeployResponse(BaseModel):
    """Response from contract deployment"""
    success: bool
    tx_hash: Optional[str] = None
    blueprint_id: Optional[str] = None
    error: Optional[str] = None


@router.get("/info", response_model=NetworkInfo)
async def get_network_info():
    """Get network connection information"""
    try:
        client = HathorClient()
        info = await client.get_network_info()
        return info
        
    except Exception as e:
        logger.error("Failed to get network info", error=str(e), exc_info=True)
        return NetworkInfo(
            network="unknown",
            node_url=None,
            connected=False,
            block_height=None,
            peer_count=None
        )


@router.post("/deploy", response_model=DeployResponse)
async def deploy_contract(request: DeployRequest):
    """Deploy contract to Hathor network"""
    try:
        logger.info("Deploying contract to network", code_length=len(request.code))
        
        client = HathorClient()
        
        # Deploy the contract
        result = await client.deploy_contract(
            code=request.code,
            private_key=request.private_key,
            blueprint_name=request.blueprint_name
        )
        
        return DeployResponse(
            success=True,
            tx_hash=result.tx_hash,
            blueprint_id=result.blueprint_id
        )
        
    except Exception as e:
        logger.error("Contract deployment failed", error=str(e), exc_info=True)
        return DeployResponse(
            success=False,
            error=str(e)
        )


@router.get("/contracts")
async def list_network_contracts():
    """List contracts deployed on network"""
    try:
        client = HathorClient()
        contracts = await client.list_contracts()
        return {"contracts": contracts}
        
    except Exception as e:
        logger.error("Failed to list network contracts", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list network contracts")