"""
Mock FastAPI server for testing the IDE without full Hathor dependencies
"""
import asyncio
import ast
from typing import Dict, Any, List
from dataclasses import dataclass

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    print("FastAPI not available. Install with: pip3 install fastapi uvicorn")
    FASTAPI_AVAILABLE = False
    exit(1)

app = FastAPI(title="Nano Contracts IDE (Mock)", version="1.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock storage
contracts_storage = {}
validation_rules = [
    {"rule": "missing_blueprint", "description": "Must inherit from Blueprint", "severity": "error"},
    {"rule": "missing_initialize", "description": "Must have initialize method", "severity": "error"},
    {"rule": "missing_decorators", "description": "Methods need @public or @view", "severity": "warning"}
]

# Pydantic models
class CompileRequest(BaseModel):
    code: str
    blueprint_name: str = "MyBlueprint"

class CompileResponse(BaseModel):
    success: bool
    blueprint_id: str = None
    errors: List[str] = []
    warnings: List[str] = []

class ValidateRequest(BaseModel):
    code: str
    strict: bool = True

class ValidationError(BaseModel):
    line: int
    column: int  
    message: str
    severity: str
    rule: str

class ValidateResponse(BaseModel):
    valid: bool
    errors: List[ValidationError] = []

class ExecuteRequest(BaseModel):
    contract_id: str
    method_name: str
    args: List[Any] = []
    kwargs: Dict[str, Any] = {}

class ExecuteResponse(BaseModel):
    success: bool
    result: Any = None
    error: str = None
    gas_used: int = None

@app.get("/")
async def root():
    return {"message": "Nano Contracts IDE Mock API", "version": "1.0.0"}

@app.get("/health")
async def health():
    return {"status": "healthy", "mode": "mock"}

@app.post("/api/contracts/compile", response_model=CompileResponse)
async def compile_contract(request: CompileRequest):
    """Mock contract compilation"""
    try:
        # Try to parse the code
        tree = ast.parse(request.code)
        
        # Simple validation
        errors = []
        warnings = []
        
        if 'Blueprint' not in request.code:
            errors.append("Contract must inherit from Blueprint")
        
        if 'initialize' not in request.code:
            errors.append("Contract must have an initialize method")
        
        if '@public' not in request.code and '@view' not in request.code:
            warnings.append("Consider adding @public or @view decorators")
        
        if errors:
            return CompileResponse(success=False, errors=errors, warnings=warnings)
        
        # Mock successful compilation
        blueprint_id = f"mock_blueprint_{len(contracts_storage) + 1}"
        contracts_storage[blueprint_id] = {
            "code": request.code,
            "blueprint_name": request.blueprint_name,
            "methods": ["initialize"]  # Mock methods
        }
        
        return CompileResponse(
            success=True, 
            blueprint_id=blueprint_id,
            warnings=warnings
        )
        
    except SyntaxError as e:
        return CompileResponse(
            success=False,
            errors=[f"Syntax error: {e.msg} at line {e.lineno}"]
        )

@app.post("/api/validation/validate", response_model=ValidateResponse)
async def validate_contract(request: ValidateRequest):
    """Mock contract validation"""
    try:
        tree = ast.parse(request.code)
        errors = []
        
        # Mock validation rules
        if 'class' not in request.code:
            errors.append(ValidationError(
                line=1, column=0,
                message="No class definition found",
                severity="error",
                rule="missing_class"
            ))
        
        if 'Blueprint' not in request.code:
            errors.append(ValidationError(
                line=1, column=0,
                message="Must inherit from Blueprint",
                severity="error", 
                rule="missing_blueprint"
            ))
            
        if 'def initialize' not in request.code:
            errors.append(ValidationError(
                line=1, column=0,
                message="Must have initialize method",
                severity="error",
                rule="missing_initialize"
            ))
        
        return ValidateResponse(valid=len(errors) == 0, errors=errors)
        
    except SyntaxError as e:
        return ValidateResponse(
            valid=False,
            errors=[ValidationError(
                line=e.lineno or 1,
                column=e.offset or 0,
                message=f"Syntax error: {e.msg}",
                severity="error",
                rule="syntax_error"
            )]
        )

@app.post("/api/contracts/execute", response_model=ExecuteResponse)  
async def execute_contract(request: ExecuteRequest):
    """Mock contract execution"""
    # Mock execution
    if request.method_name == "initialize":
        return ExecuteResponse(success=True, result=None, gas_used=100)
    elif request.method_name == "get_count":
        return ExecuteResponse(success=True, result=42, gas_used=50)
    else:
        return ExecuteResponse(success=False, error=f"Method {request.method_name} not found")

@app.get("/api/contracts/list")
async def list_contracts():
    """List compiled contracts"""
    return {"contracts": list(contracts_storage.keys())}

@app.get("/api/validation/rules")
async def get_validation_rules():
    """Get validation rules"""
    return {"rules": validation_rules}

@app.get("/api/storage/info")
async def get_storage_info():
    """Get storage info"""
    return {
        "type": "memory",
        "contracts_count": len(contracts_storage),
        "total_size": sum(len(c["code"]) for c in contracts_storage.values())
    }

if __name__ == "__main__":
    print("🚀 Starting Nano Contracts IDE Mock Server")
    print("📡 API Documentation: http://localhost:8000/docs")
    print("🔧 This is a mock server for testing without full Hathor dependencies")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")