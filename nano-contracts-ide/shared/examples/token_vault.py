"""
Token Vault Contract - Stores and manages tokens with withdrawal limits
"""
from hathor.nanocontracts import Blueprint, public, view
from hathor.nanocontracts import Context
from hathor.nanocontracts.types import (
    NCDepositAction, NCWithdrawalAction, TokenUid, Address
)


class TokenVault(Blueprint):
    """A vault that stores tokens with withdrawal limits"""
    
    # Contract state
    owner: Address
    daily_limit: int
    last_withdrawal_day: int
    withdrawn_today: int
    
    @public(allow_deposit=True)
    def initialize(self, ctx: Context, daily_limit: int) -> None:
        """Initialize the vault with a daily withdrawal limit"""
        if daily_limit <= 0:
            raise ValueError("Daily limit must be positive")
        
        caller_address = ctx.get_caller_address()
        if caller_address is None:
            raise ValueError("Only addresses can create vaults")
        
        self.owner = caller_address
        self.daily_limit = daily_limit
        self.last_withdrawal_day = 0
        self.withdrawn_today = 0
    
    @public(allow_deposit=True)
    def deposit(self, ctx: Context) -> None:
        """Deposit tokens into the vault"""
        # Tokens are automatically added to the contract balance
        # through the deposit action in the context
        pass
    
    @public(allow_withdrawal=True)
    def withdraw(self, ctx: Context, token_uid: TokenUid, amount: int) -> None:
        """Withdraw tokens from the vault within daily limits"""
        # Check ownership
        caller_address = ctx.get_caller_address()
        if caller_address != self.owner:
            raise ValueError("Only owner can withdraw")
        
        # Check amount
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        # Get current day (simplified - using timestamp / 86400)
        current_day = ctx.timestamp // 86400
        
        # Reset daily counter if it's a new day
        if current_day != self.last_withdrawal_day:
            self.withdrawn_today = 0
            self.last_withdrawal_day = current_day
        
        # Check daily limit
        if self.withdrawn_today + amount > self.daily_limit:
            raise ValueError("Daily withdrawal limit exceeded")
        
        # Check balance
        current_balance = self.syscall.get_current_balance(token_uid)
        if current_balance < amount:
            raise ValueError("Insufficient balance")
        
        # Update withdrawn amount
        self.withdrawn_today += amount
    
    @view
    def get_balance(self, token_uid: TokenUid) -> int:
        """Get the current balance of a specific token"""
        return self.syscall.get_current_balance(token_uid)
    
    @view
    def get_owner(self) -> Address:
        """Get the vault owner"""
        return self.owner
    
    @view
    def get_daily_limit(self) -> int:
        """Get the daily withdrawal limit"""
        return self.daily_limit
    
    @view
    def get_remaining_limit(self, current_timestamp: int) -> int:
        """Get remaining withdrawal limit for today"""
        current_day = current_timestamp // 86400
        
        if current_day != self.last_withdrawal_day:
            return self.daily_limit
        else:
            return self.daily_limit - self.withdrawn_today


# This is the blueprint that will be deployed
__blueprint__ = TokenVault