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
        # Look for modified code blocks in the response
        modified_pattern = r'```python:modified\n(.*?)\n```'
        modified_matches = re.findall(modified_pattern, response_text, re.DOTALL)
        
        if not modified_matches or not original_code:
            return None, None, None
        
        modified_code = modified_matches[0]  # Take the first modified code found
        
        # We'll generate the diff client-side, so just return None for diff_text
        return None, original_code, modified_code
        
    except Exception as e:
        logger.error("Failed to extract modified code from response", error=str(e))
        return None, None, None


class ChatRequest(BaseModel):
    """Request to chat with AI assistant"""
    message: str
    current_file_content: Optional[str] = None
    current_file_name: Optional[str] = None
    console_messages: List[str] = []
    context: Optional[Dict[str, Any]] = None

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
You are Clippy, a helpful AI assistant for Hathor Nano Contracts development! 📎

You are an expert in Hathor blockchain technology and nano contracts. Here's what you know:

CORE HATHOR KNOWLEDGE:
- Hathor is a scalable, decentralized, and feeless cryptocurrency with smart contract capabilities
- Nano Contracts are Hathor's smart contract platform, written in Python
- They use a Blueprint pattern where contracts are classes inheriting from Blueprint
- Methods are decorated with @public for state-changing operations or @view for read-only queries
- Context object (ctx) provides transaction information and is required for @public methods
- Contract state is defined as class attributes with type hints

NANO CONTRACT STRUCTURE:
```python
from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view

class MyContract(Blueprint):
    # State variables with type hints
    count: int
    owner: bytes
    
    @public
    def initialize(self, ctx: Context, initial_value: int) -> None:
        \"\"\"Initialize contract state\"\"\"
        self.count = initial_value
        self.owner = ctx.vertex.hash
    
    @view
    def get_count(self) -> int:
        \"\"\"Read-only method to get count\"\"\"
        return self.count
    
    @public
    def increment(self, ctx: Context, amount: int) -> None:
        \"\"\"State-changing method\"\"\"
        self.count += amount

# Export the blueprint
__blueprint__ = MyContract
```

KEY PATTERNS:
- Always export your Blueprint class as __blueprint__
- Use type hints for all state variables and method parameters
- @public methods MUST have ctx: Context as first parameter
- @view methods should NOT have ctx parameter
- Initialize all state in the initialize method
- Use ctx.vertex.hash to get caller address
- Use bytes type for addresses (32 bytes)
- Container types: dict, list are supported
- Always validate inputs and handle edge cases

COMMON GOTCHAS:
- Don't use default parameter values - not supported
- Container fields must be initialized properly: self.balances[key] = value
- Addresses are bytes, not strings
- View methods can't modify state
- Always include proper error handling

SECURITY BEST PRACTICES:
- Validate all user inputs
- Check permissions before state changes
- Prevent integer overflow/underflow
- Use proper access control patterns
- Never trust external input without validation

You help developers with:
1. Writing nano contracts
2. Debugging compilation errors
3. Understanding Hathor concepts
4. Best practices and patterns
5. Code review and optimization
6. Testing strategies

Be friendly, helpful, and use appropriate emojis! When you see code issues, offer specific suggestions with examples.

CODE MODIFICATION:
When a user requests code improvements, fixes, or modifications, provide the complete modified code in a special format.

1. If the user's message contains words like "fix", "improve", "change", "update", "modify", or "refactor", provide modified code
2. When generating code suggestions, provide BOTH a regular explanation AND the complete modified code
3. Use this EXACT format for code modifications:

```python:modified
# Complete modified code here
from hathor.nanocontracts import Blueprint
# ... rest of the modified code
```

CODE MODIFICATION RULES:
- Always return the COMPLETE file content, not just fragments
- Use the exact marker ```python:modified to identify modified code blocks
- Maintain all original code that doesn't need changes
- Keep proper indentation and formatting
- Add clear comments for significant changes
- Don't remove unrelated code or comments

EXAMPLE:
User: "Fix the increment method to validate the amount parameter"
Response: "I'll help you add validation to the increment method! Here's the updated code:

```python:modified
from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view

class SimpleCounter(Blueprint):
    count: int
    
    @public
    def initialize(self, ctx: Context) -> None:
        self.count = 0
    
    @public
    def increment(self, ctx: Context, amount: int) -> None:
        # Added validation for amount parameter
        if amount <= 0:
            raise ValueError("Amount must be positive")
        self.count += amount
    
    @view
    def get_count(self) -> int:
        return self.count

__blueprint__ = SimpleCounter
```

This adds validation to ensure the amount is positive before incrementing the counter."

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
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Use the more affordable model
            messages=[
                {"role": "system", "content": full_context},
                {"role": "user", "content": request.message}
            ],
            max_tokens=500,
            temperature=0.7
        )
        
        assistant_message = response.choices[0].message.content
        
        # Extract modified code if present
        diff_text, original_code, modified_code = extract_modified_code_from_response(
            assistant_message, 
            request.current_file_content
        )
        
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