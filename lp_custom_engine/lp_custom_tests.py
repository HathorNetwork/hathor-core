# File for testing some attributes and methods of different classes
from lp_engine_objects import *

def end_test() -> None:
    print("---------------")

def test_tx_init() -> None:
    tx = Tx(amount=50, id=0, quoted_price=20) # amount,id, price
    assert tx.current_price == tx.quoted_price
    assert tx.current_price == tx.random_price
    assert tx.current_price == 20
    assert tx.id == 0
    print("test_tx_init CORRECT")
    end_test()


def test_tx_slippage() -> None:

    tx = Tx(amount=50, id=0, quoted_price=20)  # amount, id, price
    tx.update_price(40, anti_mev=False)

    assert int(tx.slippage) == 100
    print("test_tx_slippage CORRECT [1/2]")

    tx.update_price(30, anti_mev=True)
    assert int(tx.random_slippage == 50)
    print("test_tx_slippage CORRECT [2/2]")
    end_test()


def test_tx_thread() -> None:

    # Build some swap numbers
    swaps = [10.1, -5.77, 68, 12, -0.009, 1]
    quoted_price = 20 # Price at the beginning of the block

    thread = Tx_Thread(quoted_price=quoted_price)
    thread.log_thread()  # Checks that it is empty
    tx_list = thread.build_tx_stream(swaps=swaps, quoted_price=quoted_price)
    thread.append_tx_stream(tx_list, swaps)
    print(thread.thread)
    assert len(thread.thread) == 6
    assert len(thread) == 6  # Checking dunder method
    thread.log_thread()
    print("test_tx_thread CORRECT")
    end_test()

def test_add_threads() -> None:
    Q_PRICE = 20
    thread_1 = Tx_Thread(quoted_price=Q_PRICE)
    thread_2 = Tx_Thread(quoted_price=Q_PRICE)
    swaps_1 = [20, -30, 50]
    swaps_2 = [10, 20, -40]
    tx_list_1 = thread_1.build_tx_stream(swaps=swaps_1, quoted_price=Q_PRICE)
    thread_1.append_tx_stream(tx_list_1, swaps_1)
    tx_list_2 = thread_2.build_tx_stream(swaps=swaps_2, quoted_price=Q_PRICE)
    thread_2.append_tx_stream(tx_list_2, swaps_2)


    thread_sum = thread_1 + thread_2
    thread_sum.log_thread(log_swaps=True)   
    print(thread_1.swaps) 
    print(thread_2.swaps) 
    assert len(thread_sum) == len(thread_1)
    assert len(thread_sum) == len(thread_2)

    for index, swap in enumerate(thread_sum.swaps):
        assert swap == thread_1.swaps[index] + thread_2.swaps[index]
    
    thread_sum.log_thread()

    print("test_add_threads CORRECT")
    end_test()

# --------- Test Swaps -------- #


def test_stable_swaps() -> None:
    A = 1000
    B = 2000
    Q_PRICE = B/A

    thread = Tx_Thread(Q_PRICE)
    stable_swaps = thread.stable_swaps(0, 10, 50)
    stable_tx_list = thread.build_tx_stream(stable_swaps, Q_PRICE)
    thread.append_tx_stream(stable_tx_list, stable_swaps)

    pass

def test_trade_thread() -> None:

    # We are disregarding for now the possibility of lp provision.
    AMOUNT_A = 10000
    AMOUNT_B = 20000
    NUMBER_OF_TXS = 500000
    quoted_price = AMOUNT_B/AMOUNT_A
    avg_swap = 0
    noise_spread = 1

    lp = LiquidityPool(AMOUNT_A, AMOUNT_B)
    thread = Tx_Thread(quoted_price=quoted_price)
    swaps = thread.stable_swaps(avg_swap, noise_spread, NUMBER_OF_TXS)
    tx_list = thread.build_tx_stream(swaps, quoted_price)
    thread.append_tx_stream(tx_list, swaps)

    # Make a thread of transactions (non-randomized) in the pool
    lp.trade_thread(thread, False, True)
    #thread.log_thread()

    plot_prices(thread, False)
    end_test()

def test_random_shuffle() -> None:
    AMOUNT_A = 10000
    AMOUNT_B = 20000
    NUMBER_OF_TXS = 50
    quoted_price = AMOUNT_B/AMOUNT_A
    avg_swap = 0
    noise_spread = 1

    thread = Tx_Thread(quoted_price=quoted_price)
    swaps = thread.stable_swaps(avg_swap,noise_spread, NUMBER_OF_TXS)
    tx_list = thread.build_tx_stream(swaps, quoted_price)
    thread.append_tx_stream(tx_list, swaps)
    
    # Put lp just to fetch some prices
    lp = LiquidityPool(AMOUNT_A, AMOUNT_B)
    lp.trade_thread(thread,randomized=False)

    # Print thread before randomization
    old_thread = thread.log_thread()

    thread.randomize_thread()

    # Print after randomization
    thread.log_thread()

    assert thread != old_thread

    print("test_random_shuffle CORRECT")
    end_test()


def test_link_txs() -> None:
    # Setting up
    thread = Tx_Thread(quoted_price=1)
    swaps = thread.stable_swaps(avg_swap=0, noise_spread=0.1, number_of_swaps=10)
    tx_list = thread.build_tx_stream(swaps, quoted_price=1)
    thread.append_tx_stream(tx_list=tx_list, swaps=swaps)

    # Linking the transactions of thread -> Already linked in append now.
    thread.link_txs()

    # Randomizing thread
    old_thread = thread
    thread.randomize_thread()

    old_thread.log_thread()
    print("------------")
    thread.log_thread()
    print("------------")

    thread = thread.read_by_transaction_id()
    for index, tx in enumerate(thread):
            print(f"[{index}: Tx {tx.id}: ($: {tx.amount} | Slippage: {tx.slippage:.3f}% | Random_Slippage: {tx.random_slippage} )] ->")
    print("------------")
    
    print("test_link_txs CORRECT")
    end_test()

def test_slippage_shifts() -> None:
    pass


#test_tx_init()
#test_tx_slippage()
#test_tx_thread()
#test_add_threads()
#test_trade_thread()
#test_random_shuffle()
test_link_txs()