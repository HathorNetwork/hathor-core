"""
Minimal test to verify Hathor nano contracts imports work
"""
import sys
from pathlib import Path

# Add the parent directory to path (same as our backend does)
hathor_path = Path(__file__).parent.parent.parent / "hathor"
sys.path.insert(0, str(hathor_path.parent))

print(f"Testing Hathor imports from: {hathor_path.parent}")
print("=" * 50)

# Test basic Hathor imports
try:
    from hathor.nanocontracts import Blueprint
    print("✅ Blueprint import successful")
except Exception as e:
    print(f"❌ Blueprint import failed: {e}")

try:
    from hathor.nanocontracts.custom_builtins import DISABLED_BUILTINS
    print("✅ Custom builtins import successful")
    print(f"   Found {len(DISABLED_BUILTINS)} disabled builtins")
except Exception as e:
    print(f"❌ Custom builtins import failed: {e}")

try:
    from hathor.nanocontracts.runner import Runner
    print("✅ Runner import successful")
except Exception as e:
    print(f"❌ Runner import failed: {e}")

try:
    from hathor.nanocontracts.storage import NCMemoryStorageFactory
    print("✅ Storage factory import successful")
except Exception as e:
    print(f"❌ Storage factory import failed: {e}")

try:
    from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint, Code
    print("✅ OnChainBlueprint import successful")
except Exception as e:
    print(f"❌ OnChainBlueprint import failed: {e}")

print("\n" + "=" * 50)
print("Core Hathor imports test completed!")

# Test creating a simple blueprint
print("\nTesting blueprint creation...")
try:
    simple_code = '''
from hathor.nanocontracts import Blueprint, public
from hathor.nanocontracts import Context

class TestBlueprint(Blueprint):
    value: int
    
    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 42

__blueprint__ = TestBlueprint
'''
    print("✅ Simple blueprint code created")
    
    # Try to parse it
    import ast
    tree = ast.parse(simple_code)
    print("✅ Blueprint code parses correctly")
    
except Exception as e:
    print(f"❌ Blueprint creation failed: {e}")

print("\n🎉 Basic functionality test completed!")