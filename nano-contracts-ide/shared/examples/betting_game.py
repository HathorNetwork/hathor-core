"""
Betting Game Contract - A simple betting game with HTR tokens
"""
from hathor.nanocontracts import Blueprint, public, view
from hathor.nanocontracts import Context
from hathor.nanocontracts.types import (
    NCDepositAction, NCWithdrawalAction, TokenUid, Address
)
from typing import Optional


class BettingGame(Blueprint):
    """A simple betting game where players can bet on heads or tails"""
    
    # Game state
    game_active: bool
    bet_amount: int
    heads_player: Optional[Address]
    tails_player: Optional[Address]
    heads_stake: int
    tails_stake: int
    
    @public
    def initialize(self, ctx: Context, bet_amount: int) -> None:
        """Initialize a new betting game with a fixed bet amount"""
        if bet_amount <= 0:
            raise ValueError("Bet amount must be positive")
        
        self.game_active = True
        self.bet_amount = bet_amount
        self.heads_player = None
        self.tails_player = None
        self.heads_stake = 0
        self.tails_stake = 0
    
    @public(allow_deposit=True)
    def bet_heads(self, ctx: Context) -> None:
        """Bet on heads"""
        if not self.game_active:
            raise ValueError("Game is not active")
        
        if self.heads_player is not None:
            raise ValueError("Heads position already taken")
        
        caller_address = ctx.get_caller_address()
        if caller_address is None:
            raise ValueError("Only addresses can place bets")
        
        # Check if the deposit matches the bet amount
        deposited = 0
        for action in ctx.actions_list:
            if isinstance(action, NCDepositAction):
                deposited += action.amount
        
        if deposited != self.bet_amount:
            raise ValueError(f"Must deposit exactly {self.bet_amount} HTR")
        
        self.heads_player = caller_address
        self.heads_stake = deposited
    
    @public(allow_deposit=True)
    def bet_tails(self, ctx: Context) -> None:
        """Bet on tails"""
        if not self.game_active:
            raise ValueError("Game is not active")
        
        if self.tails_player is not None:
            raise ValueError("Tails position already taken")
        
        caller_address = ctx.get_caller_address()
        if caller_address is None:
            raise ValueError("Only addresses can place bets")
        
        # Check if the deposit matches the bet amount
        deposited = 0
        for action in ctx.actions_list:
            if isinstance(action, NCDepositAction):
                deposited += action.amount
        
        if deposited != self.bet_amount:
            raise ValueError(f"Must deposit exactly {self.bet_amount} HTR")
        
        self.tails_player = caller_address
        self.tails_stake = deposited
    
    @public(allow_withdrawal=True)
    def resolve_game(self, ctx: Context, winning_side: str) -> None:
        """Resolve the game - only callable when both players have bet"""
        if not self.game_active:
            raise ValueError("Game is not active")
        
        if self.heads_player is None or self.tails_player is None:
            raise ValueError("Both players must bet before resolving")
        
        if winning_side not in ["heads", "tails"]:
            raise ValueError("Winning side must be 'heads' or 'tails'")
        
        # Determine winner and loser
        if winning_side == "heads":
            winner = self.heads_player
            winner_stake = self.heads_stake
            loser_stake = self.tails_stake
        else:
            winner = self.tails_player
            winner_stake = self.tails_stake
            loser_stake = self.heads_stake
        
        # Winner gets back their stake plus the loser's stake
        total_winnings = winner_stake + loser_stake
        
        # In a real implementation, we would need to handle the withdrawal
        # to the winner's address through the context actions
        
        # Mark game as inactive
        self.game_active = False
        
        self.log.info(f"Game resolved: {winning_side} wins {total_winnings} HTR")
    
    @view
    def get_game_status(self) -> dict:
        """Get current game status"""
        return {
            "active": self.game_active,
            "bet_amount": self.bet_amount,
            "heads_player": self.heads_player.hex() if self.heads_player else None,
            "tails_player": self.tails_player.hex() if self.tails_player else None,
            "heads_stake": self.heads_stake,
            "tails_stake": self.tails_stake,
            "total_pot": self.heads_stake + self.tails_stake
        }
    
    @view
    def can_bet_heads(self) -> bool:
        """Check if heads position is available"""
        return self.game_active and self.heads_player is None
    
    @view
    def can_bet_tails(self) -> bool:
        """Check if tails position is available"""
        return self.game_active and self.tails_player is None
    
    @view
    def can_resolve(self) -> bool:
        """Check if game can be resolved"""
        return (self.game_active and 
                self.heads_player is not None and 
                self.tails_player is not None)


# This is the blueprint that will be deployed
__blueprint__ = BettingGame