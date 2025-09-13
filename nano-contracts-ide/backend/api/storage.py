"""
Storage API router - handles storage operations and state management
"""
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

from storage.manager import StorageManager


logger = structlog.get_logger()
router = APIRouter()


class StorageInfo(BaseModel):
    """Storage information"""
    type: str
    contracts_count: int
    total_size: int


class BalanceInfo(BaseModel):
    """Balance information"""
    token_uid: str
    value: int
    can_mint: bool
    can_melt: bool


@router.get("/info", response_model=StorageInfo)
async def get_storage_info():
    """Get storage information"""
    try:
        storage = StorageManager()
        info = await storage.get_info()
        return info
        
    except Exception as e:
        logger.error("Failed to get storage info", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get storage info")


@router.post("/reset")
async def reset_storage():
    """Reset storage (clear all data)"""
    try:
        storage = StorageManager()
        await storage.reset()
        return {"message": "Storage reset successfully"}
        
    except Exception as e:
        logger.error("Failed to reset storage", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to reset storage")


@router.get("/contracts/{contract_id}/balances")
async def get_contract_balances(contract_id: str):
    """Get contract balances for all tokens"""
    try:
        storage = StorageManager()
        balances = await storage.get_contract_balances(contract_id)
        return {"balances": balances}
        
    except Exception as e:
        logger.error("Failed to get contract balances", contract_id=contract_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get contract balances")


@router.get("/contracts/{contract_id}/balance/{token_uid}")
async def get_contract_balance(contract_id: str, token_uid: str):
    """Get contract balance for specific token"""
    try:
        storage = StorageManager()
        balance = await storage.get_contract_balance(contract_id, token_uid)
        return {"balance": balance}
        
    except Exception as e:
        logger.error("Failed to get contract balance", 
                   contract_id=contract_id, token_uid=token_uid, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get contract balance")


@router.post("/contracts/{contract_id}/balance/{token_uid}/set")
async def set_contract_balance(contract_id: str, token_uid: str, balance: BalanceInfo):
    """Set contract balance for testing purposes"""
    try:
        storage = StorageManager()
        success = await storage.set_contract_balance(
            contract_id=contract_id,
            token_uid=token_uid,
            value=balance.value,
            can_mint=balance.can_mint,
            can_melt=balance.can_melt
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to set balance")
            
        return {"message": "Balance set successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to set contract balance", 
                   contract_id=contract_id, token_uid=token_uid, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to set contract balance")