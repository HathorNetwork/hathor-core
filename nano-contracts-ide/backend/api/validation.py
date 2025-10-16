"""
Validation API router - handles contract code validation
"""
from typing import List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

from validation.validator import ContractValidator


logger = structlog.get_logger()
router = APIRouter()


class ValidateRequest(BaseModel):
    """Request to validate contract code"""
    code: str
    strict: bool = True


class ValidationError(BaseModel):
    """Validation error details"""
    line: int
    column: int
    message: str
    severity: str  # "error", "warning", "info"
    rule: str


class ValidateResponse(BaseModel):
    """Response from contract validation"""
    valid: bool
    errors: List[ValidationError] = []
    suggestions: List[str] = []


@router.post("/validate", response_model=ValidateResponse)
async def validate_contract(request: ValidateRequest):
    """Validate nano contract code"""
    try:
        logger.info("Validating contract code", code_length=len(request.code))

        # Initialize validator
        validator = ContractValidator()

        # Validate the code
        result = await validator.validate_code(
            code=request.code,
            strict=request.strict
        )

        # Convert validation result to API response format
        errors = []
        for error in result.errors + result.warnings:
            errors.append(ValidationError(
                line=error.get('line', 0),
                column=error.get('column', 0),
                message=error.get('message', ''),
                severity=error.get('severity', 'error'),
                rule=error.get('rule', 'unknown')
            ))

        return ValidateResponse(
            valid=result.is_valid,
            errors=errors,
            suggestions=result.suggestions
        )

    except Exception as e:
        logger.error("Validation failed", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=400, detail=f"Validation failed: {str(e)}")


@router.get("/rules")
async def get_validation_rules():
    """Get list of validation rules"""
    try:
        validator = ContractValidator()
        rules = validator.get_validation_rules()
        return {"rules": rules}

    except Exception as e:
        logger.error("Failed to get validation rules",
                     error=str(e), exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to get validation rules")
