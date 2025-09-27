#!/usr/bin/env python3
"""Test the code extraction logic"""

import re

def extract_modified_code_from_response(response_text: str, original_code: str = None):
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
                    
                    print("WARNING: AI used regular python block instead of python:modified marker")
                    
                    # Check if this looks like a complete file (has imports and class definition)
                    if "from hathor" in modified_code or "import" in modified_code or "class" in modified_code:
                        return None, original_code, modified_code
        
        # If we found properly marked modified blocks
        elif modified_matches and original_code:
            modified_code = modified_matches[0]  # Take the first modified code found
            print("SUCCESS: Found python:modified block")
            return None, original_code, modified_code
        
        # No code modifications found
        print("NO CODE FOUND")
        return None, None, None
        
    except Exception as e:
        print(f"ERROR: {e}")
        return None, None, None

# Test case 1: With python:modified marker
test1 = """
I'll help you fix that! Here's the updated code:

```python:modified
from hathor.nanocontracts import Blueprint

class Test(Blueprint):
    pass

__blueprint__ = Test
```

This fixes the issue.
"""

# Test case 2: With regular python block
test2 = """
I'll help you fix that! Here's the updated code:

```python
from hathor.nanocontracts import Blueprint

class Test(Blueprint):
    pass

__blueprint__ = Test
```

This fixes the issue.
"""

# Test case 3: No code block
test3 = """
I'll help you understand the issue. The problem is that you need to initialize all state variables.
"""

original = "class Test: pass"

print("Test 1 (python:modified):")
result = extract_modified_code_from_response(test1, original)
print(f"Result: {result[2] is not None}\n")

print("Test 2 (regular python with modification intent):")
result = extract_modified_code_from_response(test2, original)
print(f"Result: {result[2] is not None}\n")

print("Test 3 (no code):")
result = extract_modified_code_from_response(test3, original)
print(f"Result: {result[2] is not None}\n")