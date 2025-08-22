"""
Simple test to verify backend functionality
"""
import asyncio
import sys
from pathlib import Path

# Add the current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Test imports
try:
    from validation.validator import ContractValidator
    from execution_engine.runner import ContractRunner
    from storage.manager import StorageManager
    print("✅ All imports successful!")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)


async def test_validation():
    """Test contract validation"""
    print("\n🔍 Testing contract validation...")
    
    validator = ContractValidator()
    
    # Test valid contract
    valid_code = '''
from hathor.nanocontracts import Blueprint, public, view
from hathor.nanocontracts import Context

class TestContract(Blueprint):
    count: int
    
    @public
    def initialize(self, ctx: Context, initial: int = 0) -> None:
        self.count = initial
    
    @view
    def get_count(self) -> int:
        return self.count

__blueprint__ = TestContract
'''
    
    result = await validator.validate_code(valid_code)
    print(f"Valid contract validation: {'✅ PASS' if result.is_valid else '❌ FAIL'}")
    if not result.is_valid:
        for error in result.errors:
            print(f"  Error: {error}")
    
    # Test invalid contract
    invalid_code = '''
class BadContract:
    def bad_method(self):
        print("This won't work!")
'''
    
    result = await validator.validate_code(invalid_code)
    print(f"Invalid contract validation: {'✅ PASS' if not result.is_valid else '❌ FAIL'}")


async def test_storage():
    """Test storage functionality"""
    print("\n💾 Testing storage...")
    
    storage = StorageManager()
    
    # Test storing contract
    success = await storage.store_contract(
        contract_id="test123",
        blueprint_id="blueprint123", 
        code="test code",
        methods=["initialize", "get_count"]
    )
    print(f"Store contract: {'✅ PASS' if success else '❌ FAIL'}")
    
    # Test retrieving contract
    contract = await storage.get_contract("test123")
    print(f"Retrieve contract: {'✅ PASS' if contract is not None else '❌ FAIL'}")
    
    # Test listing contracts
    contracts = await storage.list_contracts()
    print(f"List contracts: {'✅ PASS' if len(contracts) > 0 else '❌ FAIL'}")


async def test_compilation():
    """Test contract compilation"""
    print("\n⚙️ Testing contract compilation...")
    
    try:
        runner = ContractRunner()
        print("✅ Contract runner initialized")
        
        # Test simple contract
        simple_code = '''
from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view

class SimpleContract(Blueprint):
    value: int
    
    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 42
    
    @view
    def get_value(self) -> int:
        return self.value

__blueprint__ = SimpleContract
'''
        
        result = await runner.compile_contract(simple_code)
        print(f"Compile contract: {'✅ PASS' if result.success else '❌ FAIL'}")
        if not result.success:
            for error in result.errors or []:
                print(f"  Error: {error}")
    
    except Exception as e:
        print(f"❌ Compilation test failed: {e}")


async def main():
    """Run all tests"""
    print("🧪 Running Nano Contracts IDE Backend Tests")
    print("=" * 50)
    
    await test_validation()
    await test_storage()
    await test_compilation()
    
    print("\n" + "=" * 50)
    print("✅ Tests completed!")


if __name__ == "__main__":
    asyncio.run(main())