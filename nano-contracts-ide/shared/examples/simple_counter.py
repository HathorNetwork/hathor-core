"""
Simple Counter Contract - A basic nano contract example
"""
from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view


class SimpleCounter(Blueprint):
    """A simple counter that can be incremented and read"""
    
    # Contract state
    count: int
    
    @public
    def initialize(self, ctx: Context, initial_value: int) -> None:
        """Initialize the counter with an initial value"""
        self.count = initial_value
    
    @public
    def increment(self, ctx: Context, amount: int) -> None:
        """Increment the counter by the specified amount"""
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        self.count += amount
    
    @view
    def get_count(self) -> int:
        """Get the current counter value"""
        return self.count
    
    @public
    def reset(self, ctx: Context) -> None:
        """Reset the counter to zero"""
        self.count = 0


# This is the blueprint that will be deployed
__blueprint__ = SimpleCounter