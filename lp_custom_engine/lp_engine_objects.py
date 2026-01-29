# Let's build the structures for the simulator
import numpy as np
import random
from lp_utils import *

class Tx:
    """
        Transaction class for swaps within Liquidity Pool.
        For simplicity, we use token A as reference.
        If the amount swapped is "-20", then 20 tokens A have been sold and B has been bought.
        If the amount swapped is "+50", then 50 tokens A have been bought and B has been sold.    
    """
    id: int
    amount: float
    quoted_price: float
    current_price: float
    random_price: float
    slippage: float
    random_slippage: float
    next_tx: 'Tx'

    def __init__(self, id: int, amount: float, quoted_price: float ) -> None:
        """
            Builds transaction template.
        """
        if id < 0:
            raise ValueError("Transaction ID must be non-negative.") 
        
        self.id = id                            # Index of Transaction.
        self.amount = amount                    # Amount of tokens to be swapped. Negative is sellout of A, Positive is buyout of A.
        self.quoted_price = quoted_price        # Price of token at the beginning of the block (perceived price at purchase)
        self.current_price = quoted_price       # Price of token before randomization
        self.random_price = quoted_price        # Price after randomization
        self.slippage = 0                       # Slippage before randomization
        self.random_slippage = 0                # Slippage after randomization
        self.next_tx =  None                    # Linked_List null



    def update_price(self, price: int, anti_mev: bool = False) -> None:
        """
            Receives price from the liquidity pool and updates it into the transaction.
            If anti_mev flag is on, only post-randomization parameters will be altered.
            If off, only pre-randomization parameters suffer.
        """
        if anti_mev:
            self.random_price = price
            self.update_slippage(anti_mev=True)
            return 
        
        self.current_price = price
        self.update_slippage(anti_mev=False)


    def update_slippage(self, anti_mev: bool = False) -> None:
        """
            Via update of the price, the slippage of the transaction is updated.
            If anti_mev flag is on, only post-randomization parameters will be altered.
            If off, only pre-randomization parameters suffer.
        """
        q_price = self.quoted_price
        
        if anti_mev:
            r_price = self.random_price
            self.random_slippage = 100*(r_price - q_price)/q_price
            return 
        
        c_price = self.current_price
        self.slippage = 100*(c_price - q_price)/q_price
        
class Tx_Thread:
    """
        Builds transactions following a trend from a swap vector. 
    """
    thread: list[Tx]
    swaps: list[float]
    quoted_price: float
    randomized: bool
    tx_head: Tx

    def __init__(self, quoted_price: float) -> None:
        self.thread = []                    # Tx_thread. Can be randomized.
        self.swaps = []                     # History of swaps. Non-randomizable.
        self.quoted_price = quoted_price    # Price of previous block.
        self.randomized = False             # Flag if thread's been randomized earlier
        self.tx_head = None                 # Head of the Tx_List
    
    def __len__(self) -> int:
        return len(self.thread)

    def __add__(self, other:'Tx_Thread') -> 'Tx_Thread':
        """
            Adding means overlapping the effects on swapping, elementwise.
        """
        if len(self) != len(other):
            raise ValueError(f"Lengths of threads not equal - {len(self)} != {len(other)}")
        
        if len(self.swaps) != len(other.swaps):
            raise ValueError(f"Lengths of swaps not equal - {len(self.swaps)} != {len(other.swaps)}")

        if self.quoted_price != other.quoted_price:
            raise Exception(f"Quoted_prices are different - {self.quoted_price} != {other.quoted_price}")
        
        # Eventually put Numpy into the mix to make it more efficient.
        swaps = []
        for id, swap in enumerate(self.swaps):
            swaps.append(swap + other.swaps[id])
        # ----- #
        thread = self.build_tx_stream(swaps, self.quoted_price)
        tx_thread = Tx_Thread(quoted_price=self.quoted_price)
        tx_thread.thread = thread
        tx_thread.swaps = swaps
        return tx_thread

    def log_thread(self, log_swaps=False) -> None:
        """
            Gives the log on the current thread of transactions.
        """
        if log_swaps:
            print(self.swaps)
            return 
        
        thread = self.thread

        for index, tx in enumerate(thread):
            print(f"[{index}: Tx {tx.id}: ($: {tx.amount} | Slippage: {tx.slippage:.3f}% | Random_Slippage: {tx.random_slippage} )] ->")
        

    def build_tx_stream(self, swaps: list[float], quoted_price: float) -> list[Tx]:
        """
            From a list of swaps, turn them into transactions. 
        """
        tx_stream: list[Tx] = []

        for index, swap in enumerate(swaps):
            tx = Tx(index, swap, quoted_price)
            tx_stream.append(tx)
        
        return tx_stream
        
    def append_tx_stream(self, tx_list: list[Tx], swaps: list[float]) -> None:
        """
            Add swaps as a transaction batch as a thread. Also keep the swaps in the tx_thread.
        """
        if len(tx_list) != len(swaps):
            raise ValueError(f"Length of tx_list {len(tx_list) } !=  Length of swap list {len(swaps)}")
        
        for index, tx in enumerate(tx_list):
            self.thread.append(tx)
            self.swaps.append(swaps[index])

        # Link the transactions by their ids
        self.link_txs()


    def randomize_thread(self) -> None:
        """
            Get self.thread and randomize its order. 
            If will only be called if there is already a thread, and each Tx has 
            its own id.
        """
        if not self.thread:
            raise Exception("No self.thread to randomize.")

        random.shuffle(self.thread)
        # Note -> Eventually we need to randomize the swaps as well.
        self.randomized = True

    def get_slippages(self) -> list[float]:
        """
            Return the slippage values in a list for all transactions in a thread.
            If the thread has been randomized, return random_slippage values.
        """

        tx_list = self.thread
        randomized = self.randomized
        return [tx.random_slippage if randomized else tx.slippage for tx in tx_list]

    def get_slippages_by_tx_id(self, id: int) -> list[float] | None:
        """
            Gets the slippages of a given transaction by its ID, travelling through the linked list.
        """
        if id < 0:
            raise ValueError("Id must be non-negative")
        
        tx = self.tx_head
        while tx:
            if tx.id == id:
                return (tx.random_slippage, tx.slippage)
            tx = tx.next_tx
        return None


    def stable_swaps(self, avg_swap: float, noise_spread: float, number_of_swaps: int) -> None:
        """
            Average trend of purchase is stale (locked in average, aside from noise).
        """
        if number_of_swaps <= 0:
            raise ValueError(f"stable_swaps: number of swaps must be bigger than zero: {number_of_swaps} <= 0")

        if avg_swap == 0: 
            epsilon = 10**-18 # Constant in case avg swap is zero, so to avoid swapping no tokens.
            avg_swap += epsilon

        # Get gaussian noise
        if noise_spread < 0:
            raise ValueError("Noise must be non-negative")

        noise = np.random.normal(0, noise_spread, number_of_swaps)
 
        # Get average swap 
        swaps = np.ones_like(noise)*avg_swap
        swaps += noise
        swaps = swaps.tolist()

        return swaps

    def bull_swaps(self, rate: float, noise_spread: float, number_of_swaps: int) -> list[float]:
        """
        Token B gets bought progressively.
        rate: Rate of increase of purchases (~slope)
        """

        if rate <= 0:
            raise ValueError("Rate must be positive")


        return self.stable_swaps(rate, noise_spread, number_of_swaps) 

    def bear_swaps(self, rate: float, noise_spread: float, number_of_swaps: int) -> list[float]:
        """
        Token B gets sold progressively.
        rate: Rate of increase of purchases (~slope)
        """

        if rate >= 0:
            raise ValueError("Rate must be negative")


        return self.stable_swaps(rate, noise_spread, number_of_swaps) 

    def oscillate_swaps(self, frequency: int, amplitude: int, swap_0: int) -> None:
        """
            Give a general trend of oscillation (sine, cosine, ...) aside from noise.
        """
        pass

    def link_txs(self) -> None:
        """
            Given a batch of transactions, we link them, in case we need to recoup
            their order after randomization.
        """
        if self.randomized:
            raise Exception("Thread has been randomized - no linking possible.")

        tx_list = self.thread
        length = len(tx_list)
        self.tx_head = tx_list[0]

        for index, tx in enumerate(tx_list):
            if index < length - 1:
                tx.next_tx = tx_list[index + 1]
                continue
            tx.next_tx = None

    def read_by_transaction_id(self) -> list[Tx]:
        """
            Reads the transactions randomized via linked list.
            The linked list must be set beforehand, and it is used to grab back the order of set.
        """
        tx_list: list[Tx] = []

        if not self.tx_head:
            return tx_list

        tx = self.tx_head

        while True:
            tx_list.append(tx)
            if not tx.next_tx:
                break
            tx = tx.next_tx

        return tx_list  

"""
    Thoughts:
    1. We have the liquidity pool giving the prices. 
    2. Each transaction that passes should change the liquidity pool, incrementally.
    3. Should we have:
        a. The Tx_Thread object, separate to the Liquidity Pool, which is just "an object" which reacts?
            i. We would need to reset the liquidity pool then afterward
        b. Nah I guess a is the way. Let Tx_Thread just be the factory and conversion method between numbers and transactions.
"""

class LiquidityPool:
    """
        Liquidity Pool for A and B pairing.
        Every token swap which swaps a positive amount BUYS token A. 
        Likewise, negative swaps mean to sell A.

        The LP class is stateless until the end of the block.

    """
    amount_a: float
    amount_b: float
    constant: float
    quoted_price: float
    
    def __init__(self, amount_a: float, amount_b: float) -> None:

        if amount_a <= 0 or amount_b < 0:
            raise ValueError("No amount can be zero or less.")

        self.amount_a = amount_a
        self.amount_b = amount_b
        self.constant = amount_a*amount_b
        self.quoted_price = amount_b/amount_a # Price of A in terms of B.
    
    def trade_thread(self, thread: Tx_Thread, randomized: bool = False, change_state: bool = False) -> None:
        """
            Provide the prices for each transaction in the order given by Tx Thread.
            delta_B = -(B*delta_A/(A + delta_A)) is the amount provided of token B given token A amount.
        """
        amount_a = self.amount_a
        amount_b = self.amount_b
        quoted_price = amount_b/amount_a # Price of A in terms of B.

        # Iter through tx_list to get the changing prices
        tx_list = thread.thread
        for tx in tx_list:

            delta_amount_a = -tx.amount # Buy = positive A = less A in the pool.
            amount_a += delta_amount_a

            # Current price must include delta_a to precisely measure price.
            current_price = amount_b/amount_a
            delta_amount_b = -current_price*delta_amount_a

            # One increases, the other decreases.
            amount_b += delta_amount_b

            tx_slippage = get_slippage(current_price, quoted_price)
            if randomized:
                tx.random_price = current_price
                tx.random_slippage = tx_slippage
                continue
            
            tx.current_price = current_price
            tx.slippage = tx_slippage

        if change_state:
            self.confirm_state_transition(amount_a, amount_b)


    def confirm_state_transition(self, new_amount_a: float, new_amount_b: float) -> None:
        """
            Liquidity Pool does not alter state until the end of the block.

        """
        if new_amount_a <= 0 or new_amount_b < 0:
            raise ValueError("No amount can be zero or less.")
        
        self.amount_a = new_amount_a
        self.amount_b = new_amount_b

        if new_amount_a*new_amount_b != self.constant:
            print(f"Liquidity Altered: diff_K = {new_amount_a*new_amount_b - self.constant}")
            self.constant = new_amount_a*new_amount_b

    def get_quoted_price(self) -> float:
        return self.quoted_price


# We need to get the prices swapped.
# Here are the general equations absed on price and slippage:

# p_k = p_1*(1 + s_k) (where s_k is not in percentage)
# x_k = x_1 + sum(swaps)
# y_k = p_1*(s_k + 1)*x_k



