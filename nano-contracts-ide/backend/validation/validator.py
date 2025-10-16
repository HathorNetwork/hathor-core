"""
Contract Validation System - Direct integration with Hathor's validation
"""
import structlog
from hathor.nanocontracts.types import NC_INITIALIZE_METHOD, NC_FALLBACK_METHOD
from hathor.nanocontracts.exception import BlueprintSyntaxError
from hathor.nanocontracts.custom_builtins import (
    DISABLED_BUILTINS,
    AST_NAME_BLACKLIST,
    EXEC_BUILTINS
)
from hathor.nanocontracts.blueprint_syntax_validation import (
    validate_has_self_arg,
    validate_has_ctx_arg,
    validate_has_not_ctx_arg,
    validate_method_types
)
import sys
import ast
from typing import Dict, Any, List
from dataclasses import dataclass
from pathlib import Path

# Add the parent directory to Python path to import hathor modules
hathor_path = Path(__file__).parent.parent.parent.parent / "hathor"
sys.path.insert(0, str(hathor_path.parent))

# Import Hathor validation modules directly


logger = structlog.get_logger()


@dataclass
class ValidationError:
    """Validation error details"""
    line: int
    column: int
    message: str
    severity: str  # "error", "warning", "info"
    rule: str


@dataclass
class ValidationResult:
    """Result of contract validation"""
    is_valid: bool
    errors: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]
    suggestions: List[str]


class ASTValidator(ast.NodeVisitor):
    """AST validator for nano contract restrictions"""

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.suggestions = []

    def visit_Name(self, node):
        """Check for forbidden names"""
        if node.id in AST_NAME_BLACKLIST:
            self.errors.append({
                'line': node.lineno,
                'column': node.col_offset,
                'message': f"Use of '{node.id}' is forbidden in nano contracts",
                'severity': 'error',
                'rule': 'forbidden_name'
            })

        if node.id in DISABLED_BUILTINS:
            self.errors.append({
                'line': node.lineno,
                'column': node.col_offset,
                'message': f"Builtin '{node.id}' is disabled in nano contracts",
                'severity': 'error',
                'rule': 'disabled_builtin'
            })

        self.generic_visit(node)

    def visit_Import(self, node):
        """Check import restrictions"""
        for alias in node.names:
            if not alias.name.startswith('typing'):
                self.errors.append({
                    'line': node.lineno,
                    'column': node.col_offset,
                    'message': f"Direct imports are not allowed. Use 'from {alias.name} import ...' instead",
                    'severity': 'error',
                    'rule': 'import_restriction'
                })

        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Check from-import restrictions"""
        if node.module:
            # Check if the module is in allowed imports
            # This would need to be expanded with the actual allowed imports list
            allowed_modules = ['typing', 'dataclasses', 'enum']
            if node.module not in allowed_modules:
                self.warnings.append({
                    'line': node.lineno,
                    'column': node.col_offset,
                    'message': f"Import from '{node.module}' may not be allowed in production",
                    'severity': 'warning',
                    'rule': 'import_check'
                })

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        """Check function definitions for nano contract requirements"""
        # Check if this is a potential nano contract method
        if hasattr(node, 'decorator_list') and node.decorator_list:
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name):
                    if decorator.id in ['public', 'view', 'fallback']:
                        self._validate_method(node, decorator.id)

        self.generic_visit(node)

    def _validate_method(self, node, decorator_type):
        """Validate nano contract method"""
        try:
            # Check basic requirements (simplified validation)
            if len(node.args.args) == 0:
                self.errors.append({
                    'line': node.lineno,
                    'column': node.col_offset,
                    'message': f"@{decorator_type} method must have 'self' argument",
                    'severity': 'error',
                    'rule': 'missing_self'
                })
                return

            # Check first argument is 'self'
            if node.args.args[0].arg != 'self':
                self.errors.append({
                    'line': node.lineno,
                    'column': node.col_offset,
                    'message': f"@{decorator_type} method first argument must be 'self'",
                    'severity': 'error',
                    'rule': 'invalid_self'
                })

            # Check context argument for public/fallback methods
            if decorator_type in ['public', 'fallback']:
                if len(node.args.args) < 2:
                    self.errors.append({
                        'line': node.lineno,
                        'column': node.col_offset,
                        'message': f"@{decorator_type} method must have Context argument",
                        'severity': 'error',
                        'rule': 'missing_context'
                    })

            # Check return type annotation
            if not node.returns:
                self.warnings.append({
                    'line': node.lineno,
                    'column': node.col_offset,
                    'message': f"Method '{node.name}' should have return type annotation",
                    'severity': 'warning',
                    'rule': 'missing_return_type'
                })

        except Exception as e:
            logger.error("Method validation error", error=str(e))

    def visit_ClassDef(self, node):
        """Check class definitions for Blueprint requirements"""
        # Check if this inherits from Blueprint
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == 'Blueprint':
                self._validate_blueprint_class(node)
                break

        self.generic_visit(node)

    def _validate_blueprint_class(self, node):
        """Validate Blueprint class requirements"""
        # Check for required initialize method
        has_initialize = False

        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                if item.name == NC_INITIALIZE_METHOD:
                    has_initialize = True
                    # Check if initialize has @public decorator
                    has_public = any(
                        isinstance(d, ast.Name) and d.id == 'public'
                        for d in item.decorator_list
                    )
                    if not has_public:
                        self.errors.append({
                            'line': item.lineno,
                            'column': item.col_offset,
                            'message': f"'{NC_INITIALIZE_METHOD}' method must be annotated with @public",
                            'severity': 'error',
                            'rule': 'initialize_not_public'
                        })

        if not has_initialize:
            self.errors.append({
                'line': node.lineno,
                'column': node.col_offset,
                'message': f"Blueprint class must have an '{NC_INITIALIZE_METHOD}' method",
                'severity': 'error',
                'rule': 'missing_initialize'
            })


class ContractValidator:
    """Main contract validation system"""

    def __init__(self):
        logger.info("Contract validator initialized")

    async def validate_code(self, code: str, strict: bool = True) -> ValidationResult:
        """Validate nano contract source code"""
        try:
            logger.info("Validating contract code",
                        code_length=len(code), strict=strict)

            # Parse the AST
            try:
                tree = ast.parse(code)
            except SyntaxError as e:
                return ValidationResult(
                    is_valid=False,
                    errors=[{
                        'line': e.lineno or 0,
                        'column': e.offset or 0,
                        'message': f"Syntax error: {e.msg}",
                        'severity': 'error',
                        'rule': 'syntax_error'
                    }],
                    warnings=[],
                    suggestions=["Check your Python syntax"]
                )

            # Run AST validation
            validator = ASTValidator()
            validator.visit(tree)

            # Additional semantic checks
            self._run_semantic_checks(code, validator)

            is_valid = len(validator.errors) == 0

            if not is_valid:
                validator.suggestions.extend([
                    "Check the nano contracts documentation for valid patterns",
                    "Ensure all methods are properly decorated with @public, @view, or @fallback",
                    "Make sure your Blueprint class inherits from Blueprint base class"
                ])

            return ValidationResult(
                is_valid=is_valid,
                errors=validator.errors,
                warnings=validator.warnings,
                suggestions=validator.suggestions
            )

        except Exception as e:
            logger.error("Validation failed", error=str(e), exc_info=True)
            return ValidationResult(
                is_valid=False,
                errors=[{
                    'line': 0,
                    'column': 0,
                    'message': f"Validation error: {str(e)}",
                    'severity': 'error',
                    'rule': 'validation_error'
                }],
                warnings=[],
                suggestions=[]
            )

    def _run_semantic_checks(self, code: str, validator: ASTValidator):
        """Run additional semantic validation checks"""
        try:
            # Check if code defines a Blueprint class
            if 'class' not in code or 'Blueprint' not in code:
                validator.warnings.append({
                    'line': 1,
                    'column': 0,
                    'message': "Code should define a Blueprint class",
                    'severity': 'warning',
                    'rule': 'no_blueprint_class'
                })

            # Check for proper imports
            if 'from hathor.nanocontracts' not in code and 'import' in code:
                validator.suggestions.append(
                    "Consider importing required nano contract types: 'from hathor.nanocontracts import Blueprint, public, view'"
                )

        except Exception as e:
            logger.error("Semantic checks failed", error=str(e))

    def get_validation_rules(self) -> List[Dict[str, Any]]:
        """Get list of validation rules"""
        return [
            {
                "rule": "forbidden_name",
                "description": "Certain names are forbidden in nano contracts",
                "severity": "error"
            },
            {
                "rule": "disabled_builtin",
                "description": "Some Python builtins are disabled for security",
                "severity": "error"
            },
            {
                "rule": "import_restriction",
                "description": "Only specific imports are allowed",
                "severity": "error"
            },
            {
                "rule": "missing_self",
                "description": "Methods must have 'self' as first parameter",
                "severity": "error"
            },
            {
                "rule": "missing_context",
                "description": "Public methods must have Context parameter",
                "severity": "error"
            },
            {
                "rule": "missing_initialize",
                "description": "Blueprint must have initialize method",
                "severity": "error"
            },
            {
                "rule": "missing_return_type",
                "description": "Methods should have return type annotations",
                "severity": "warning"
            }
        ]
