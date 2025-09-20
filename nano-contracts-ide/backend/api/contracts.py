"""
Contracts API router - handles contract compilation, execution, and management
"""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
import structlog

from execution_engine.runner import ContractRunner
from validation.validator import ContractValidator
from storage.manager import StorageManager


logger = structlog.get_logger()
router = APIRouter()


class CompileRequest(BaseModel):
    """Request to compile a contract"""
    code: str
    blueprint_name: Optional[str] = "MyBlueprint"


class CompileResponse(BaseModel):
    """Response from contract compilation"""
    success: bool
    blueprint_id: Optional[str] = None
    errors: List[str] = []
    warnings: List[str] = []
    gas_estimate: Optional[int] = None


class ExecuteRequest(BaseModel):
    """Request to execute a contract method"""
    contract_id: str
    method_name: str
    args: List[Any] = []
    kwargs: Dict[str, Any] = {}
    actions: List[Dict[str, Any]] = []
    context: Optional[Dict[str, Any]] = None
    caller_address: Optional[str] = None  # Optional caller address for multi-user testing
    method_type: Optional[str] = None  # 'public' or 'view'


class ExecuteResponse(BaseModel):
    """Response from contract execution"""
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    gas_used: Optional[int] = None
    logs: List[str] = []
    state_changes: Dict[str, Any] = {}


class ContractInfo(BaseModel):
    """Contract information"""
    contract_id: str
    blueprint_id: str
    code: str
    methods: List[str] = []
    created_at: Optional[str] = None


@router.post("/compile", response_model=CompileResponse)
async def compile_contract(request: CompileRequest):
    """Compile a nano contract from source code"""
    try:
        logger.info("Compiling contract", code_length=len(request.code))

        # Initialize validator
        validator = ContractValidator()

        # Validate the contract code
        validation_result = await validator.validate_code(request.code)

        if not validation_result.is_valid:
            return CompileResponse(
                success=False,
                errors=validation_result.errors,
                warnings=validation_result.warnings
            )

        # Get singleton runner and compile
        runner = ContractRunner.get_instance()
        compile_result = await runner.compile_contract(
            code=request.code,
            blueprint_name=request.blueprint_name
        )

        # Check if compilation actually succeeded
        if not compile_result.success:
            return CompileResponse(
                success=False,
                errors=compile_result.errors,
                warnings=compile_result.warnings
            )

        return CompileResponse(
            success=True,
            blueprint_id=compile_result.blueprint_id,
            warnings=[warning.get('message', str(warning)) for warning in validation_result.warnings],
            gas_estimate=compile_result.gas_estimate
        )

    except Exception as e:
        logger.error("Contract compilation failed",
                     error=str(e), exc_info=True)
        raise HTTPException(
            status_code=400, detail=f"Compilation failed: {str(e)}")


@router.post("/execute", response_model=ExecuteResponse)
async def execute_contract(request: ExecuteRequest):
    """Execute a contract method"""
    try:
        logger.info("Executing contract method",
                    contract_id=request.contract_id,
                    method=request.method_name)

        # Get singleton runner
        runner = ContractRunner.get_instance()

        # Execute the method
        execution_result = await runner.execute_method(
            contract_id=request.contract_id,
            method_name=request.method_name,
            args=request.args,
            kwargs=request.kwargs,
            actions=request.actions,
            context=request.context,
            caller_address=request.caller_address,
            method_type=request.method_type
        )

        return ExecuteResponse(
            success=execution_result.success,
            result=execution_result.result,
            error=execution_result.error,
            gas_used=execution_result.gas_used,
            logs=execution_result.logs,
            state_changes=execution_result.state_changes
        )

    except Exception as e:
        logger.error("Contract execution failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=400, detail=f"Execution failed: {str(e)}")


@router.get("/list", response_model=List[ContractInfo])
async def list_contracts():
    """List all deployed contracts"""
    try:
        storage = StorageManager()
        contracts = await storage.list_contracts()
        return contracts

    except Exception as e:
        logger.error("Failed to list contracts", error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list contracts")


@router.get("/{contract_id}", response_model=ContractInfo)
async def get_contract(contract_id: str):
    """Get contract information"""
    try:
        storage = StorageManager()
        contract = await storage.get_contract(contract_id)

        if not contract:
            raise HTTPException(status_code=404, detail="Contract not found")

        return contract

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get contract",
                     contract_id=contract_id, error=str(e), exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get contract")


@router.delete("/{contract_id}")
async def delete_contract(contract_id: str):
    """Delete a contract"""
    try:
        storage = StorageManager()
        success = await storage.delete_contract(contract_id)

        if not success:
            raise HTTPException(status_code=404, detail="Contract not found")

        return {"message": "Contract deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete contract",
                     contract_id=contract_id, error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to delete contract")


@router.get("/{contract_id}/methods")
async def get_contract_methods(contract_id: str):
    """Get contract methods information"""
    try:
        runner = ContractRunner.get_instance()
        methods = await runner.get_contract_methods(contract_id)
        return {"methods": methods}

    except Exception as e:
        logger.error("Failed to get contract methods",
                     contract_id=contract_id, error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to get contract methods")


@router.get("/{contract_id}/state")
async def get_contract_state(contract_id: str):
    """Get contract state"""
    try:
        storage = StorageManager()
        state = await storage.get_contract_state(contract_id)
        return {"state": state}

    except Exception as e:
        logger.error("Failed to get contract state",
                     contract_id=contract_id, error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to get contract state")
