"""
AI Assistant API router - handles AI assistant requests with Hathor-specific knowledge
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog
import openai
import os
import re
import difflib
from datetime import datetime

logger = structlog.get_logger()
router = APIRouter()

def extract_modified_code_from_response(response_text: str, original_code: str = None) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Extract modified code from AI response.
    Returns (diff_text, original_code, modified_code)
    """
    try:
        # First, look for properly marked modified code blocks
        modified_pattern = r'```python:modified\n(.*?)\n```'
        modified_matches = re.findall(modified_pattern, response_text, re.DOTALL)
        
        # If no python:modified blocks found, try regular python blocks as fallback
        if not modified_matches:
            # Check if the response seems to be providing a code modification
            modification_indicators = [
                "here's the updated", "here's the modified", "here's the fixed",
                "updated code", "modified code", "fixed code", "complete code",
                "here is the updated", "here is the modified", "here is the fixed"
            ]
            
            has_modification_intent = any(indicator in response_text.lower() for indicator in modification_indicators)
            
            if has_modification_intent:
                # Try to find regular python blocks
                regular_pattern = r'```python\n(.*?)\n```'
                regular_matches = re.findall(regular_pattern, response_text, re.DOTALL)
                
                if regular_matches and original_code:
                    # Use the regular python block as modified code
                    modified_code = regular_matches[0]
                    
                    # Log warning that AI didn't use proper marker
                    logger.warning("AI used regular python block instead of python:modified marker")
                    
                    # Check if this looks like a complete file (has imports and class definition)
                    if "from hathor" in modified_code or "import" in modified_code or "class" in modified_code:
                        return None, original_code, modified_code
        
        # If we found properly marked modified blocks
        elif modified_matches and original_code:
            modified_code = modified_matches[0]  # Take the first modified code found
            return None, original_code, modified_code
        
        # No code modifications found
        return None, None, None
        
    except Exception as e:
        logger.error("Failed to extract modified code from response", error=str(e))
        return None, None, None


class ChatMessage(BaseModel):
    """Individual chat message"""
    role: str  # 'user' or 'assistant'
    content: str

class ChatRequest(BaseModel):
    """Request to chat with AI assistant"""
    message: str
    current_file_content: Optional[str] = None
    current_file_name: Optional[str] = None
    console_messages: List[str] = []
    context: Optional[Dict[str, Any]] = None
    conversation_history: List[ChatMessage] = []  # Recent conversation history

class ChatResponse(BaseModel):
    """Response from AI assistant"""
    success: bool
    message: str
    error: Optional[str] = None
    suggestions: List[str] = []
    original_code: Optional[str] = None  # Original code
    modified_code: Optional[str] = None  # Modified code

# Hathor-specific system prompt
HATHOR_SYSTEM_PROMPT = """
🚨 CRITICAL DIFF GENERATION RULE: When users ask for code changes, fixes, improvements, or modifications, you MUST use ```python:modified for the complete updated file content. This is mandatory for the IDE diff system to work.

You are Clippy, a helpful AI assistant for Hathor Nano Contracts development! 📎

You are an expert in Hathor blockchain technology and nano contracts with comprehensive knowledge of the Blueprint SDK. Here's what you know:

CORE HATHOR KNOWLEDGE:
- Hathor is a scalable, decentralized, and feeless cryptocurrency with smart contract capabilities
- Nano Contracts are Hathor's smart contract platform, written in Python 3.11
- They use a Blueprint pattern where contracts are classes inheriting from Blueprint
- Methods are decorated with @public for state-changing operations or @view for read-only queries
- Context object (ctx) provides transaction information and is required for @public methods
- Contract state is defined as class attributes with type hints

BLUEPRINT SDK TYPE SYSTEM:
- Address: bytes (20 bytes wallet address)
- Amount: int (token amounts, last 2 digits are decimals, e.g., 1025 = 10.25 tokens)
- BlueprintId: bytes (32 bytes blueprint identifier)
- ContractId: bytes (32 bytes contract identifier)
- TokenUid: bytes (32 bytes token identifier)
- Timestamp: int (Unix epoch seconds)
- VertexId: bytes (32 bytes transaction identifier)
- TxOutputScript: bytes (transaction output lock script)
- NCAction: union type for actions (deposit, withdrawal, grant/acquire authority)

NANO CONTRACT STRUCTURE:
```python
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view, Address, Amount, TokenUid

class MyContract(Blueprint):
    # State variables with type hints (MUST be fully parameterized)
    count: int
    owner: Address
    balances: dict[Address, Amount]
    token_uid: TokenUid
    
    @public
    def initialize(self, ctx: Context, initial_value: int, token: TokenUid) -> None:
        \"\"\"Initialize contract state - MUST initialize ALL state variables\"\"\"
        # Initialize ALL state variables declared above
        self.count = initial_value
        self.owner = ctx.vertex.hash  # Use ctx.vertex.hash for caller
        # Container fields start empty automatically - DO NOT assign self.balances = {}
        self.token_uid = token
    
    @view
    def get_count(self) -> int:
        \"\"\"Read-only method to get count\"\"\"
        return self.count
    
    @view
    def get_balance(self, address: Address) -> Amount:
        \"\"\"Get balance for address\"\"\"
        return self.balances.get(address, 0)
    
    @public
    def increment(self, ctx: Context, amount: int) -> None:
        \"\"\"State-changing method\"\"\"
        if amount <= 0:
            raise ValueError("Amount must be positive")
        self.count += amount

# Export the blueprint
__blueprint__ = MyContract
```

EXTERNAL INTERACTIONS (via self.syscall):
- get_contract_id(): get own contract ID
- get_blueprint_id(contract_id=None): get blueprint ID
- get_balance_before_current_call(token_uid=None, contract_id=None): balance before current call
- get_current_balance(token_uid=None, contract_id=None): current balance including actions
- can_mint(token_uid, contract_id=None): check mint authority
- can_melt(token_uid, contract_id=None): check melt authority
- mint_tokens(token_uid, amount): mint tokens
- melt_tokens(token_uid, amount): melt tokens
- create_token(name, symbol, amount, mint_authority=True, melt_authority=True): create new token
- call_view_method(contract_id, method_name, *args, **kwargs): call other contract view method
- call_public_method(contract_id, method_name, actions, *args, **kwargs): call other contract public method
- create_contract(blueprint_id, salt, actions, *args, **kwargs): create new contract
- emit_event(data): emit event (max 100 KiB)

RANDOM NUMBER GENERATION (via self.syscall.rng):
- randbits(bits): random int in [0, 2^bits)
- randbelow(n): random int in [0, n)
- randrange(start, stop, step=1): random int in [start, stop) with step
- randint(a, b): random int in [a, b]
- choice(seq): random element from sequence
- random(): random float in [0, 1)

LOGGING (via self.log):
- debug(message, **kwargs): DEBUG log
- info(message, **kwargs): INFO log
- warn(message, **kwargs): WARN log
- error(message, **kwargs): ERROR log

ACTION HANDLING:
- @public methods must specify allowed actions: allow_deposit, allow_withdrawal, allow_grant_authority, allow_acquire_authority
- Or use allow_actions=[NCActionType.DEPOSIT, NCActionType.WITHDRAWAL]
- Access actions via ctx.actions (mapping of TokenUid to tuple of actions)
- Use ctx.get_single_action(token_uid) to get single action for a token

CONTEXT OBJECT:
- ctx.vertex.hash: Address or ContractId of caller (use this for caller identity)
- ctx.timestamp: Timestamp of first confirming block
- ctx.vertex: VertexData of origin transaction
- ctx.actions: mapping of TokenUid to actions
- ctx.get_single_action(token_uid): get single action for token

KEY PATTERNS:
- Always export your Blueprint class as __blueprint__
- Use type hints for all state variables and method parameters (MANDATORY)
- @public methods MUST have ctx: Context as first parameter
- @view methods should NOT have ctx parameter
- Initialize all state variables in the initialize method
- Use ctx.vertex.hash to get caller address (this is the standard way)
- Use bytes type for addresses (20 bytes), contracts (32 bytes), tokens (32 bytes)
- Container types must be fully parameterized: dict[str, int], list[Address], etc.
- Always validate inputs and handle edge cases
- Multi-token balances controlled by Hathor engine, not direct contract code

IMPORT CONSTRAINTS:
- Only use allowed imports from hathor.nanocontracts package
- Use `from x import y` syntax, not `import x`
- Standard library: math.ceil, math.floor, typing.Optional, typing.NamedTuple, collections.OrderedDict

FORBIDDEN FEATURES:
- try/except blocks (not supported)
- async/await (not allowed)
- Special methods (__init__, __str__, etc.)
- Built-in functions: exec, eval, open, input, globals, locals
- Class attributes (only instance attributes)

CRITICAL INITIALIZATION RULES:
- ALL state variables declared at class level MUST be initialized in @public initialize() method
- Container fields (dict, list, set) are AUTOMATICALLY initialized as empty - DO NOT assign to them
- NEVER write: self.balances = {} or self.items = [] in initialize() - they start empty automatically
- You can ONLY modify container contents AFTER contract creation: self.balances[key] = value
- Trying to assign to container fields will cause: AttributeError: cannot set a container field
- Uninitialized state variables will cause AttributeError when accessed
- Never define custom __init__() methods - use initialize() instead

METHOD TYPES & DECORATORS:
- @public: state-changing methods, requires Context, can receive actions
- @view: read-only methods, no Context parameter, cannot modify state
- @fallback: special method for handling non-existent method calls
- Internal methods: no decorator, can be called by other methods

CONTRACT LIFECYCLE:
1. Contract creation via initialize() method with required parameters
2. Public method calls can modify state and handle token actions
3. View method calls for reading state (no modifications)
4. Balance updates happen automatically after successful public method execution

SECURITY & BEST PRACTICES:
- Validate all user inputs in public methods
- Check permissions before state changes (use ctx.vertex.hash for caller identity)
- Handle token actions properly (deposits/withdrawals/authorities)
- Use proper access control patterns
- Prevent integer overflow/underflow
- Never trust external input without validation
- Use self.log for debugging and audit trails

ADVANCED FEATURES:
- Oracles via SignedData[T] parameter type
- Inter-contract communication via syscall methods
- Token creation and authority management
- Event emission for off-chain monitoring
- Deterministic randomness via syscall.rng

TESTING & DEBUGGING:
- Use self.log methods for execution logging
- Test both success and failure scenarios  
- Validate state changes after method execution
- Check balance updates work correctly
- Ensure proper error handling with NCFail exceptions

CRITICAL ERROR PATTERNS TO AVOID:
- NEVER assign to container fields in initialize(): self.balances = {} will fail!
- NEVER use ctx.address - use ctx.vertex.hash instead for caller identity
- NEVER try to modify container fields directly during initialization
- Container fields start empty automatically - you can only modify their contents later
- If you get "AttributeError: cannot set a container field" - remove the assignment!
- If you get "Context object has no attribute 'address'" - use ctx.vertex.hash instead!

You help developers with:
1. Writing nano contracts following Blueprint SDK patterns
2. Debugging compilation and execution errors
3. Understanding Hathor concepts and type system
4. Best practices and security patterns  
5. Code review and optimization
6. Action handling and token operations
7. Testing strategies and debugging

🔥 CODE MODIFICATION (MANDATORY RULE):
When users request code changes, fixes, improvements, or modifications, you MUST use this EXACT format:

```python:modified
# Complete modified file content here
from hathor.nanocontracts.blueprint import Blueprint
# ... all the updated code ...
__blueprint__ = ClassName
```

TRIGGER WORDS requiring python:modified:
"fix", "change", "update", "modify", "improve", "add", "remove", "implement", "apply changes", "do the changes", "make the changes"

❌ NEVER use regular ```python blocks for code modifications
✅ ALWAYS use ```python:modified for any code the user should apply to their file

This triggers the IDE's diff viewer - essential for the system to work properly!

Be friendly, helpful, and use appropriate emojis! When you see code issues, offer specific suggestions with examples.
"""

@router.post("/chat", response_model=ChatResponse)
async def chat_with_assistant(request: ChatRequest):
    """Chat with the AI assistant"""
    try:
        logger.info("AI assistant chat request", message_length=len(request.message))
        
        # Check if OpenAI API key is configured
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            # Return a mock response if no API key
            return ChatResponse(
                success=True,
                message="Hi! I'm Clippy, your Hathor Nano Contracts assistant! 📎\n\n" +
                       "I'd love to help you with your nano contracts, but I need an OpenAI API key to be fully functional. " +
                       "For now, here are some quick tips:\n\n" +
                       "• Always use @public for state-changing methods\n" +
                       "• Use @view for read-only methods\n" +
                       "• Include type hints for all variables\n" +
                       "• Export your class as __blueprint__\n\n" +
                       "Set the OPENAI_API_KEY environment variable to enable full AI assistance!",
                suggestions=[
                    "Add proper type hints to your contract",
                    "Use @public decorator for state-changing methods", 
                    "Check the initialize method implementation",
                    "Validate user inputs in your methods"
                ]
            )
        
        # Prepare the context for the AI
        context_parts = [HATHOR_SYSTEM_PROMPT]
        
        # Add current file context if available
        if request.current_file_content and request.current_file_name:
            context_parts.append(f"\nCURRENT FILE: {request.current_file_name}\n```python\n{request.current_file_content}\n```")
        
        # Add console messages if available (recent errors/warnings)
        if request.console_messages:
            recent_messages = request.console_messages[-5:]  # Last 5 messages
            context_parts.append(f"\nRECENT CONSOLE MESSAGES:\n" + "\n".join(recent_messages))
        
        # Add any additional context
        if request.context:
            context_parts.append(f"\nADDITIONAL CONTEXT: {request.context}")
        
        full_context = "\n".join(context_parts)
        
        # Call OpenAI API
        client = openai.OpenAI(api_key=api_key)
        
        # Build messages array with conversation history
        messages = [{"role": "system", "content": full_context}]
        
        # Add recent conversation history (limit to last 6 messages to stay within token limits)
        recent_history = request.conversation_history[-6:] if request.conversation_history else []
        for msg in recent_history:
            messages.append({"role": msg.role, "content": msg.content})
        
        # Add current message
        messages.append({"role": "user", "content": request.message})
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Use the more affordable model
            messages=messages,
            max_tokens=2000,  # Increased to ensure complete code responses
            temperature=0.3  # Lower temperature for more consistent formatting
        )
        
        assistant_message = response.choices[0].message.content
        
        # Debug log the assistant response
        logger.info(f"AI response preview: {assistant_message[:200]}...")
        logger.info(f"Response contains python:modified: {'```python:modified' in assistant_message}")
        logger.info(f"Response contains regular python: {'```python' in assistant_message}")
        
        # Extract modified code if present
        diff_text, original_code, modified_code = extract_modified_code_from_response(
            assistant_message, 
            request.current_file_content
        )
        
        # Log extraction results
        logger.info(f"Extraction results - has original: {original_code is not None}, has modified: {modified_code is not None}")
        
        # Generate helpful suggestions based on the response
        suggestions = []
        if "error" in request.message.lower() or any("error" in msg.lower() for msg in request.console_messages):
            suggestions.extend([
                "Check your method decorators (@public/@view)",
                "Verify type hints and parameter types",
                "Ensure proper initialization of state variables"
            ])
        
        if request.current_file_content:
            if "@public" not in request.current_file_content:
                suggestions.append("Consider adding @public methods for state changes")
            if "@view" not in request.current_file_content:
                suggestions.append("Add @view methods for read-only operations")
            if "__blueprint__" not in request.current_file_content:
                suggestions.append("Don't forget to export your class as __blueprint__")
        
        return ChatResponse(
            success=True,
            message=assistant_message,
            suggestions=list(set(suggestions)),  # Remove duplicates
            original_code=original_code,
            modified_code=modified_code
        )
        
    except Exception as e:
        logger.error("AI assistant chat failed", error=str(e), exc_info=True)
        return ChatResponse(
            success=False,
            error=f"Assistant unavailable: {str(e)}",
            message="Sorry, I'm having trouble right now! 😅 But here are some general tips:\n\n" +
                   "• Make sure your contract inherits from Blueprint\n" +
                   "• Use proper decorators (@public/@view)\n" +
                   "• Include the initialize method\n" +
                   "• Export as __blueprint__ at the end",
            suggestions=[
                "Check Hathor nano contracts documentation",
                "Review the example contracts", 
                "Ensure proper Python syntax"
            ]
        )

@router.get("/suggestions")
async def get_suggestions():
    """Get general suggestions for nano contract development"""
    return {
        "suggestions": [
            "Always validate user inputs in your methods",
            "Use proper access control patterns",
            "Include comprehensive error handling", 
            "Write clear docstrings for all methods",
            "Test your contracts thoroughly before deployment",
            "Follow Hathor naming conventions",
            "Use type hints for better code clarity",
            "Consider gas costs in complex operations"
        ]
    }

@router.get("/examples")
async def get_examples():
    """Get example nano contract patterns"""
    return {
        "examples": [
            {
                "name": "Token Contract",
                "description": "A basic token with transfer and balance functionality",
                "category": "Financial"
            },
            {
                "name": "Voting Contract", 
                "description": "Democratic voting with proposal and ballot tracking",
                "category": "Governance"
            },
            {
                "name": "Escrow Contract",
                "description": "Secure multi-party transactions with dispute resolution",
                "category": "Financial"
            },
            {
                "name": "Registry Contract",
                "description": "Store and manage key-value data with access control",
                "category": "Utility"
            }
        ]
    }