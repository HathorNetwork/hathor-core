"""
Multi-User Token Contract - A sophisticated nano contract demonstrating multiple caller interactions
Supports minting, transferring, approvals, and address-specific balances
"""
from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view


class MultiUserToken(Blueprint):
    """
    A token contract that supports multiple users with different permissions
    Features: minting, transfers, approvals, balance tracking per address
    """
    
    # Contract state
    name: str
    symbol: str
    total_supply: int
    owner: bytes
    balances: dict[bytes, int]
    allowances: dict[bytes, dict[bytes, int]]  # owner -> spender -> amount
    
    @public
    def initialize(self, ctx: Context, name: str, symbol: str, initial_supply: int) -> None:
        """Initialize the token contract"""
        self.name = name
        self.symbol = symbol
        self.total_supply = initial_supply
        self.owner = ctx.vertex.hash  # Contract creator becomes owner
        self.balances = {self.owner: initial_supply}
        self.allowances = {}
    
    @view
    def get_balance(self, address: bytes) -> int:
        """Get token balance of an address"""
        return self.balances.get(address, 0)
    
    @view
    def get_total_supply(self) -> int:
        """Get total token supply"""
        return self.total_supply
    
    @view
    def get_owner(self) -> bytes:
        """Get contract owner address"""
        return self.owner
    
    @view
    def get_allowance(self, owner: bytes, spender: bytes) -> int:
        """Get approved amount that spender can transfer from owner"""
        return self.allowances.get(owner, {}).get(spender, 0)
    
    @public
    def mint(self, ctx: Context, to_address: bytes, amount: int) -> None:
        """Mint new tokens (only owner can mint)"""
        caller = ctx.vertex.hash
        
        if caller != self.owner:
            raise ValueError("Only owner can mint tokens")
        
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        # Update balances and total supply
        current_balance = self.balances.get(to_address, 0)
        self.balances[to_address] = current_balance + amount
        self.total_supply += amount
    
    @public
    def transfer(self, ctx: Context, to_address: bytes, amount: int) -> None:
        """Transfer tokens from caller to another address"""
        caller = ctx.vertex.hash
        
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        caller_balance = self.balances.get(caller, 0)
        if caller_balance < amount:
            raise ValueError(f"Insufficient balance. Have {caller_balance}, need {amount}")
        
        # Update balances
        self.balances[caller] = caller_balance - amount
        to_balance = self.balances.get(to_address, 0)
        self.balances[to_address] = to_balance + amount
    
    @public
    def approve(self, ctx: Context, spender: bytes, amount: int) -> None:
        """Approve spender to transfer tokens on behalf of caller"""
        caller = ctx.vertex.hash
        
        if amount < 0:
            raise ValueError("Amount cannot be negative")
        
        # Initialize nested dicts if needed
        if caller not in self.allowances:
            self.allowances[caller] = {}
        
        self.allowances[caller][spender] = amount
    
    @public
    def transfer_from(self, ctx: Context, from_address: bytes, to_address: bytes, amount: int) -> None:
        """Transfer tokens from one address to another using allowance"""
        caller = ctx.vertex.hash
        
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        # Check allowance
        allowed_amount = self.allowances.get(from_address, {}).get(caller, 0)
        if allowed_amount < amount:
            raise ValueError(f"Insufficient allowance. Allowed {allowed_amount}, need {amount}")
        
        # Check balance
        from_balance = self.balances.get(from_address, 0)
        if from_balance < amount:
            raise ValueError(f"Insufficient balance. Have {from_balance}, need {amount}")
        
        # Update allowance
        self.allowances[from_address][caller] = allowed_amount - amount
        
        # Update balances
        self.balances[from_address] = from_balance - amount
        to_balance = self.balances.get(to_address, 0)
        self.balances[to_address] = to_balance + amount
    
    @view
    def get_all_balances(self) -> dict[bytes, int]:
        """Get all non-zero balances (for debugging)"""
        return {addr: balance for addr, balance in self.balances.items() if balance > 0}


# This is the blueprint that will be deployed
__blueprint__ = MultiUserToken