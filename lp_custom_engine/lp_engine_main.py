# First draft of simulation
from lp_engine_objects import *
from lp_utils import *
#import numpy as np // LATER --> Fix imports on NUMPY and PYTEST.

## Okay so what do we need to have here:

'''

1. A Liquidity Pool to change tokens with

A <--> B
It is inspired by UniSwap V2 --> Constant Product AMM x*y = k

Rules:

x0*y0 = k_0, where k_0 may only be altered by providing liquidity.

We keep as a reference the first token (A), and use the signal as reference:

SWAP:
--> If +20, buys 20 A by selling B
--> If -50, sells 50 A by buying B.

Add Liquidity: Add a and b = a*p(b, a) = a*y/x.
Remove Liquidity: Analogous



2. A transaction bundle 
    2.1. Tx Id
    2.2. Amount to be swapped (all in token A)
        --> Remember - if the amount is negative, we sell A, hence buy B, and vice-versa.
    2.2. Quoted Price (given by the block)
    2.3. Current Price (Measured from the Liquidity Pool) --> This gives the slippage
    2.4. Post-Random Price (Reconstruct the prices) --> This gives the random_slippage
    2.5. Slippage
    2.6. Post-Random Slippage

When we get a thread of Txs, we may just do a single passage and compare both slippages.
    

3. A list of transactions generated with a general trend of prices
    The trend generation will be thought later. 

'''

# Liquidity Pool initialization
TOKEN_A_AMOUNT = 10000
TOKEN_B_AMOUNT = 20000
CONSTANT = TOKEN_A_AMOUNT*TOKEN_B_AMOUNT
NUMBER_OF_TRANSACTIONS = 100


lp = LiquidityPool(TOKEN_A_AMOUNT, TOKEN_B_AMOUNT)

QUOTED_PRICE = lp.get_quoted_price() # Price of A in terms of B

# Tx_Thread - Transactions in a block
thread = Tx_Thread(quoted_price=QUOTED_PRICE)

stable_swaps = thread.stable_swaps(avg_swap=0, noise_spread=10, number_of_swaps=NUMBER_OF_TRANSACTIONS)
stable_tx_batch = thread.build_tx_stream(stable_swaps, quoted_price=QUOTED_PRICE)

thread.append_tx_stream(stable_tx_batch, stable_swaps)
thread.log_thread()
thread.log_thread(log_swaps=True)

plot_swaps(swaps=stable_swaps)


