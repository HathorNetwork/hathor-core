from lp_utils import *
from lp_engine_objects import *
from matplotlib import pyplot as plt
import numpy as np

"""
    Scripts module for implementing complex actions with the
    objects given.
"""

# ---- Control Panel ---- #
NUMBER_OF_TXS: int = 10
POOL_PERCENT: float = 0.05 / 100  # Percentage of the Pool 
AMOUNT_A: float = 1000000
AMOUNT_B: float = 2000000
NOISE_SPREAD: float= POOL_PERCENT*AMOUNT_A
AVG_SWAP: float = NOISE_SPREAD/2    #  -std/2 < AVG_SWAP < std/2 ideally.
# ----------------------- #

CONSTANT: float = AMOUNT_A*AMOUNT_B
QUOTED_PRICE: float = AMOUNT_B/AMOUNT_A


def set_liquidity_pool(amount_a: float, amount_b: float) -> LiquidityPool:
    if amount_a <= 0:
        raise ValueError("Only positive values for amounts and transaction numbers")

    if amount_b <= 0:
        raise ValueError("Only positive values for amounts and transaction numbers")
    
    lp = LiquidityPool(amount_a, amount_b)
    return lp

def set_tx_thread(amount_a: float = AMOUNT_A, amount_b: float = AMOUNT_B,
                   number_of_txs: int = NUMBER_OF_TXS, avg_swap: float=AVG_SWAP,
                     noise_spread: float = NOISE_SPREAD) -> Tx_Thread:
    """
    Reusable boilerplate: bootstraps the transaction thread object in a more convenient manner.
    
    :param amount_a: Description
    :type amount_a: float
    :param amount_b: Description
    :type amount_b: float
    :param number_of_txs: Description
    :type number_of_txs: int
    :param avg_swap: Description
    :type avg_swap: float
    :param noise_spread: Description
    :type noise_spread: float
    :return: Description
    :rtype: Tx_Thread
    """

    quoted_price = amount_b/amount_a
    avg_swap = avg_swap
    noise_spread = noise_spread

    # Create the tx_thread
    thread = Tx_Thread(quoted_price)
    swaps = thread.stable_swaps(avg_swap, noise_spread, number_of_txs)
    tx_list = thread.build_tx_stream(swaps, quoted_price)
    thread.append_tx_stream(tx_list, swaps)

    return thread



def trade_and_random_trade(thread: Tx_Thread, lp: LiquidityPool, plot: bool = False) -> None:
    """
        Makes a Tx_Thread which interacts with a LP two times:
        1. One to get the original prices it would obtain if not randomized:
        2. A second time to fill the random_slippage parameters and see how the slippage
        has shifted. Only after this shift the liquidity pool may have its state altered.
    """
    lp.trade_thread(thread, randomized=False, change_state=False)
    slippages = thread.get_slippages()

    thread.randomize_thread()

    lp.trade_thread(thread, randomized=True, change_state=False)
    r_slippages = thread.get_slippages()

    # While this doesn't show the difference in slippage per transaction, let's see 
    # how the price curve changes
    if not plot:
        return
    plt.figure()
    plt.plot(slippages, label="Pre-Shuffling")
    plt.plot(r_slippages, label="Post-Shuffling")
    plt.xlabel("Number of Transactions", fontsize=14)
    plt.ylabel("Slippage [%]", fontsize=14)
    plt.title("Pre-Shuffling v.s. Post-Shuffling Slippages")
    plt.grid(True)
    plt.legend()
    plt.show()

# Question for later: does liquidity provision within a block make the r_s and s curves 
# NOT coincide at the end?b

# Does liquidity provision dampen the curve?

# Note: We could stack the model limit plot, to check that none leaks out of the 
# theoretical limits.

def get_slippage_shift(tx_thread: Tx_Thread) -> None:
    """
        Get the slippage shift for each id due to randomization.
    """
    tx_list = tx_thread.read_by_transaction_id()
    slippage_shift = np.array([tx.random_slippage - tx.slippage for tx in tx_list])
    #slippage_shift = np.where(slippage_shift < 0, 0, slippage_shift).tolist()
    return slippage_shift
    

def average_shifts(amount_a: int, amount_b: int, number_of_txs: int,
                    avg_swap: float = 0, noise_spread: float = 1, iterations: int = 100,
                      show: bool = True, index:int=1, sum : bool = True,
                      legend: bool = True) -> list[float]:
    """
        Script for generating multiple random transaction batches, and
        computing the slippage shift pre and post randomization. 
    """
    lp = set_liquidity_pool(amount_a, amount_b)
    tx_thread = set_tx_thread(amount_a, amount_b, number_of_txs, avg_swap, noise_spread)
    shift_long_array = list()
    for _ in range(iterations):
        trade_and_random_trade(tx_thread, lp)
        shift = get_slippage_shift(tx_thread)
        shift_long_array.append(shift)

    if sum:
        shift_long_array = np.array(shift_long_array).reshape(iterations, number_of_txs)
        avg_shift = shift_long_array.sum(axis=0)/iterations
    else:
        avg_shift = shift_long_array

    
    if show:
        #plt.plot(avg_shift, 'o', alpha=0.2, label=f"{np.sqrt(amount_a*amount_b)/1000:.0f} kLP", color='black')
        plt.plot(avg_shift, alpha=0.3, label=f"{np.sqrt(amount_a*amount_b)/1000:.0f} kLP", color='black')
        plt.xlabel("Number of Transactions", fontsize=14)
        plt.ylabel("Slippage Shift [%]", fontsize=14)
        plt.title("Average Shift")
        if legend:
            plt.legend()
        plt.grid(True)
        plt.savefig(f"./images/avg_shifts/it_{iterations}_ntxs_{number_of_txs}_liq_{np.sqrt(amount_a*amount_b)/1000000:.0f}_{index}.pdf")
    
    return avg_shift


def change_liquidity() -> None:
    pass


def shifts_by_liquidity() -> None:
    """
        Hardcoded script to build slippage shift plots, varying the liquidity of the pool.. 
    """
    plt.figure(figsize=(8,6))
    index=3
    iterations = 1
    average_shifts(AMOUNT_A/10, AMOUNT_B/10, NUMBER_OF_TXS, AVG_SWAP, NOISE_SPREAD, iterations)
    average_shifts(AMOUNT_A, AMOUNT_B, NUMBER_OF_TXS, AVG_SWAP, NOISE_SPREAD, iterations)
    average_shifts(AMOUNT_A*10, AMOUNT_B*10, NUMBER_OF_TXS, AVG_SWAP, NOISE_SPREAD, iterations, show=True, index=index)

def same_state_cloud(n_times: int = 10, n_txs: int = NUMBER_OF_TXS) -> None:
    """
    Plot the same configurations of average shifts multiple times, to create a plot of multiple test cases in tandem.
    """
    n_times = int(n_times) # Ensures integer status to n_times. 
    n_txs = int(n_txs) # Ensures integer status to n_times. 
    if n_times <= 0 or n_txs <= 0:
        raise ValueError("Value must be a positive integer.")
    
    amount_a = AMOUNT_A
    amount_b = AMOUNT_B
    avg_swap = AVG_SWAP
    noise_spread = NOISE_SPREAD
    plt.figure(figsize=(8,6))
    long_shifts = []
    for _ in range(n_times):
        shifts = average_shifts(amount_a, amount_b, n_txs,
                        avg_swap, noise_spread, iterations=1,
                          show=False, index=99, legend=False)
        long_shifts = np.append(long_shifts, shifts)

    plt.title(f"Avg. Slippage Shift |{n_txs} Txs")
    plt.ylabel("Slippage Shift [%]")
    plt.xlabel("Number of Transactions")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.show()
    bins = np.arange(-0.2, 0.201, 0.01)
    plt.hist(np.array(long_shifts), bins=bins, edgecolor='black', density=False, alpha=0.7)
    plt.title(f"Avg. Swap: {avg_swap} | {n_txs} Tx's per batch | {n_times} iterations")
    plt.xlabel("Slippage Shift")
    plt.ylabel("Counts")
    plt.show()


def shift_histograms() -> None:
    n_txs = 5000
    iter = 100
    avg = 0
    noise = 1
    d_bin = 0.001
    bin_limit = 0.5
    bin_spread = np.arange(-bin_limit, bin_limit + d_bin, d_bin).tolist()
    shifts = average_shifts(AMOUNT_A, AMOUNT_B, n_txs, avg_swap=avg, noise_spread=noise, iterations=iter, show=False)
    plt.hist(shifts, bins = bin_spread, color="skyblue", edgecolor="black")
    shifts = average_shifts(AMOUNT_A, AMOUNT_B, n_txs, avg_swap=avg + 10, noise_spread=noise, iterations=iter, show=False)
    plt.hist(shifts, bins = bin_spread, color="lightcoral", edgecolor="black")
    plt.title(f"Avg. Slippage Shift: {iter} Iterations, {n_txs} Txs, {np.sqrt(AMOUNT_A*AMOUNT_B)/1000000:.2f} MLP")
    plt.xlabel("Slippage Shift [%]")
    plt.ylabel("Frequency")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.show()

def increase_avg_histograms() -> None:
    """
        Script for increasing the average per swap and obtain different histograms.
    Docstring for increase_avg_histograms
    """
    amount_a = AMOUNT_A
    amount_b = AMOUNT_B
    number_of_hists = 5
    percent_of_A_per_swap = 0.01
    n_txs = 500
    iter = 100
    avg = percent_of_A_per_swap*amount_a/100
    d_avg = avg
    noise = avg/5

    d_bin = 0.05
    bin_limit = 5
    bin_spread = np.arange(-bin_limit, bin_limit + d_bin, d_bin).tolist()
    for i in range(number_of_hists):
        shifts = average_shifts(amount_a, amount_b, n_txs, avg_swap=avg + i*d_avg, noise_spread=noise, iterations=iter, show=False, sum=True) # Error in Sum false
        plt.hist(shifts, bins = bin_spread, alpha=0.5, label = f'Avg. Swap (%): {d_avg*i*100/amount_a + percent_of_A_per_swap}')
    plt.title(f"Avg. Slippage Shift, Swap Flux: {avg/AMOUNT_A*1000000}u, {iter} Iter., {n_txs} Txs, {np.sqrt(amount_a*amount_b)/1000000:.2f} MLP")
    plt.xlabel("Slippage Shift [%]")
    plt.ylabel("Frequency")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.legend()
    plt.show()


def increase_number_txs_histograms() -> None:
    #Check for different avg swaps
    amount_a = AMOUNT_A
    amount_b = AMOUNT_B
    number_of_hists = 5
    n_txs = 1000
    iter = 100
    avg = 20
    d_txs = 3000
    noise = avg*0.1 + 2
    d_bin = 0.01
    bin_limit = 5
    bin_spread = np.arange(-bin_limit, bin_limit + d_bin, d_bin).tolist()
    for i in range(number_of_hists):
        shifts = average_shifts(amount_a, amount_b, n_txs + i*d_txs, avg_swap=avg, noise_spread=noise, iterations=iter, show=False)
        plt.hist(shifts, bins = bin_spread, alpha=0.4, label = f'N_txs: {d_txs*i + n_txs}')
    plt.title(f"Avg. Slippage Shift, Swap Flux: {avg/AMOUNT_A*1000000}u, {iter} Iter., {n_txs} Txs, {np.sqrt(amount_a*amount_b)/1000000:.2f} MLP")
    plt.xlabel("Slippage Shift [%]")
    plt.ylabel("Frequency")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.legend()
    plt.show()

def increase_noise_histograms() -> None:
    # If the ratio of noise to iteractions is too low, it spreads.
    amount_a = AMOUNT_A
    amount_b = AMOUNT_B
    number_of_hists = 5
    n_txs = 5000
    iter = 100
    avg = 0
    noise = 0
    d_noise = 25
    d_bin = 0.001
    bin_limit = 0.2
    bin_spread = np.arange(-bin_limit, bin_limit + d_bin, d_bin).tolist()
    for i in range(number_of_hists):
        shifts = average_shifts(amount_a, amount_b, n_txs, avg_swap=avg, noise_spread=noise + i*d_noise, iterations=iter, show=False)
        plt.hist(shifts, bins = bin_spread, edgecolor="black", alpha=0.6, label = f'Avg. Noise: {d_noise*i + noise}')
    plt.title(f"Avg. Slippage Shift: {iter} Iterations, {n_txs} Txs, {np.sqrt(amount_a*amount_b)/1000000:.2f} MLP")
    plt.xlabel("Slippage Shift [%]")
    plt.ylabel("Frequency")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.legend()
    plt.show()


def sweep_transactions(n_times: int = 2000, n_txs: list[int] = (10, 20, 30, 40, 50, 60, 70, 80, 90, 100),
      amount_a: int = AMOUNT_A, amount_b: int = AMOUNT_B,
      avg_swap: float = AVG_SWAP, noise_spread: float = NOISE_SPREAD, slip_lims: float = 0.1) -> None:
    
    n_times = int(n_times) # Ensures integer status to n_times. 
    slip_lims = abs(slip_lims)
    if n_times <= 0 or slip_lims <= 0:
        raise ValueError("Value must be a positive integer.")
    
    
    n_shifts = []
    long_shifts = []
    within_margin = np.zeros_like(n_txs)
    within_twice_margin = np.zeros_like(n_txs)
    for index, n_tx in enumerate(n_txs):
        if n_tx <= 0:
            raise ValueError("N_tx must be positive")
        for _ in range(n_times):
            shifts = average_shifts(amount_a, amount_b, n_tx,
                            avg_swap, noise_spread, iterations=1,
                            show=False, index=75, legend=False)
            long_shifts = np.append(long_shifts, shifts)
        for x in long_shifts:
            if x > slip_lims or x < -slip_lims:
                within_margin[index] += 1
            if x > 2*slip_lims or x < -2*slip_lims:
                within_twice_margin[index] += 1
        n_shifts.append(long_shifts)

    bins = np.arange(-1.00, 1.00, 0.02)
    for index, array in enumerate(n_shifts):
        weights = 100*np.ones_like(array)/len(array)
        counts, _, _ = plt.hist(np.array(array), bins=bins, weights=weights, edgecolor='black', density=False, alpha=0.5,
                 label=f'{n_txs[index]} txs,  {100*within_margin[index]/len(array):.1f}%, {100*within_twice_margin[index]/len(array):.1f}%')
        if index == 0:
            values = counts
    plt.title(f"Avg. Swap: {f'+{avg_swap/NOISE_SPREAD:.1f}' if avg_swap > 0 else f'{avg_swap/NOISE_SPREAD:.1f}'} std.'s | std. = {POOL_PERCENT*100}% |{n_times} iterations", fontsize=13)
    plt.xlabel("Slippage Shift", fontsize=13)
    plt.ylabel(" [%] of Total Swaps", fontsize=13)
    plt.xticks(fontsize=13)
    plt.yticks(fontsize=13)
    plt.grid(True, linestyle='--', alpha=0.5)
    #colors = ['green', 'blue']
    #for index, each in enumerate([slip_lims, 2*slip_lims]):
    #    plt.plot([-each, -each],[0, np.max(values)/2], linestyle='--', linewidth=3, color=colors[index], label=f"{each}% shift", alpha=0.5)
    #    plt.plot([each, each],[0, np.max(values)/2], linestyle='--', linewidth=3, color=colors[index], alpha=0.5)
    plt.legend()
    plt.show()


def sweep_avg(n_times: int = 2000, n_txs: list[int] = (10, 25, 50, 100),
      amount_a: int = AMOUNT_A, amount_b: int = AMOUNT_B,
      avg_swap_list: float = [0, NOISE_SPREAD/4, NOISE_SPREAD/2], noise_spread: list[float] = NOISE_SPREAD, slip_lims: float = 0.1) -> None:
    
    n_times = int(n_times) # Ensures integer status to n_times. 
    slip_lims = abs(slip_lims)
    if n_times <= 0 or slip_lims <= 0:
        raise ValueError("Value must be a positive integer.")
    
    
    
    colors = ['red', 'blue', 'green', 'yellow', 'brown', 'pink', 'grey', 'black']
    alphas = [0.5, 0.4, 0.3]
    for k, avg_swap_k in enumerate(avg_swap_list):
        n_shifts = []
        long_shifts = []
        within_margin = np.zeros_like(n_txs)
        within_twice_margin = np.zeros_like(n_txs)
        for index, n_tx in enumerate(n_txs):
            if n_tx <= 0:
                raise ValueError("N_tx must be positive")
            for _ in range(n_times):
                shifts = average_shifts(amount_a, amount_b, n_tx,
                                avg_swap_k, noise_spread, iterations=1,
                                show=False, index=75, legend=False)
                long_shifts = np.append(long_shifts, shifts)
            for x in long_shifts:
                if x > slip_lims or x < -slip_lims:
                    within_margin[index] += 1
                if x > 2*slip_lims or x < -2*slip_lims:
                    within_twice_margin[index] += 1
            n_shifts.append(long_shifts)

        bins = np.arange(-1.00, 1.00, 0.02)
        
        values = []
        for ind, array in enumerate(n_shifts):
            weights = 100*np.ones_like(array)/len(array)
            counts, _, _ = plt.hist(np.array(array), bins=bins, weights=weights, edgecolor='black', density=False, alpha=alphas[k%len(alphas)],
                    label=f'{n_txs[ind]} txs,  {100*within_margin[ind]/len(array):.1f}%, {100*within_twice_margin[ind]/len(array):.1f}%',
                    color= colors[k%len(colors)])
            if ind == 0:
                values = counts
    avgList = []
    for x in avg_swap_list:
        avgList.append(x/NOISE_SPREAD)
    plt.title(f"Avg. Swap: {avgList} std.'s | std. = {POOL_PERCENT*100}% |{n_times} iterations", fontsize=13)
    plt.xlabel("Slippage Shift", fontsize=13)
    plt.ylabel(" [%] of Total Swaps", fontsize=13)
    plt.xticks(fontsize=13)
    plt.yticks(fontsize=13)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend()
    plt.show()


def sweep_std(n_times: int = 2000, n_txs: list[int] = (5, 10, 25),
      amount_a: int = AMOUNT_A, amount_b: int = AMOUNT_B, noise_spread: list[float] = [NOISE_SPREAD], slip_lims: float = 0.1) -> None:
    
    n_times = int(n_times) # Ensures integer status to n_times. 
    slip_lims = abs(slip_lims)
    if n_times <= 0 or slip_lims <= 0:
        raise ValueError("Value must be a positive integer.")
    
    
    
    colors = ['red', 'blue', 'green', 'yellow', 'brown', 'pink', 'grey', 'black']
    alphas = [0.5, 0.4, 0.3, 0.25, 0.25, 0.25, 0.25]
    for k, sigma in enumerate(noise_spread):
        avg_swap = sigma/2
        n_shifts = []
        long_shifts = []
        within_margin = np.zeros_like(n_txs)
        within_twice_margin = np.zeros_like(n_txs)
        for index, n_tx in enumerate(n_txs):
            if n_tx <= 0:
                raise ValueError("N_tx must be positive")
            for _ in range(n_times):
                shifts = average_shifts(amount_a, amount_b, n_tx,
                                avg_swap, sigma, iterations=1,
                                show=False, index=75, legend=False)
                long_shifts = np.append(long_shifts, shifts)
            for x in long_shifts:
                if x > slip_lims or x < -slip_lims:
                    within_margin[index] += 1
                if x > 2*slip_lims or x < -2*slip_lims:
                    within_twice_margin[index] += 1
            n_shifts.append(long_shifts)

        bins = np.arange(-1.00, 1.00, 0.02)
        
        values = []
        for ind, array in enumerate(n_shifts):
            weights = 100*np.ones_like(array)/len(array)
            counts, _, _ = plt.hist(np.array(array), bins=bins, weights=weights, edgecolor='black', density=False, alpha=alphas[k%len(alphas)],
                    label=f'{n_txs[ind]} txs,  {100*within_margin[ind]/len(array):.1f}%, {100*within_twice_margin[ind]/len(array):.1f}%',
                    color= colors[k%len(colors)])
            if ind == 0:
                values = counts
    avgList = []
    for x in noise_spread:
        avgList.append(x/(NOISE_SPREAD*100))
    colors = ['gold', 'black']
    for index, each in enumerate([slip_lims, 2*slip_lims]):
        plt.plot([-each, -each],[0, np.max(values)/2], linestyle='--', linewidth=3, color=colors[index], label=f"{each}% shift", alpha=0.5)
        plt.plot([each, each],[0, np.max(values)/2], linestyle='--', linewidth=3, color=colors[index], alpha=0.8)
    plt.title(f"Std. = {avgList}% |{n_times} it.", fontsize=13)
    plt.xlabel("Slippage Shift", fontsize=13)
    plt.ylabel(" [%] of Total Swaps", fontsize=13)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend()
    plt.show()

def sweep_avg_and_std(n_iterations: int = 2000, n_txs: list[int] = (10, 25, 50, 100),
      amount_a: int = AMOUNT_A, amount_b: int = AMOUNT_B,
      avg_swap_list: float = [0, NOISE_SPREAD/4, NOISE_SPREAD/2],
      noise_spread: list[float] = [NOISE_SPREAD], slip_lims: float = 0.1) -> None:
    """
    Sweeps varying average AND standard deviation of the transaction data set, stacking their histograms in the same plot.
    
    :param n_times: Description
    :type n_times: int
    :param n_txs: Description
    :type n_txs: list[int]
    :param amount_a: Description
    :type amount_a: int
    :param amount_b: Description
    :type amount_b: int
    :param avg_swap_list: Description
    :type avg_swap_list: float
    :param noise_spread: Description
    :type noise_spread: list[float]
    :param slip_lims: Description
    :type slip_lims: float
    """
    avg_swap_list = np.array([0, 0.25, 0.5])
    n_iterations = int(n_iterations) # Ensures integer status to n_iterations. 
    slip_lims = abs(slip_lims)
    if n_iterations <= 0 or slip_lims <= 0:
        raise ValueError("Value must be a positive integer.")
    
    colors = ['red', 'blue', 'green', 'yellow', 'brown', 'pink', 'grey', 'black']   # Color schema for number of transactions
    slip_colors = ['blue', 'green', 'yellow', 'orange', 'red']                      # Color schema for slippage thresholds
    alphas = [0.5, 0.4, 0.3, 0.25, 0.25, 0.25, 0.25]

    for q, avg_swap_k in enumerate(avg_swap_list):
        for k, sigma in enumerate(noise_spread):
            avg_swap = avg_swap_k*sigma
            n_shifts = []
            n_shifts, (within_margin, within_twice_margin) = compute_all_shifts(amount_a, amount_b, avg_swap_k, sigma, n_txs, n_iterations, slip_lims)

            bins = np.arange(-1.00, 1.00, 0.02)
            values = []

            # Build a weighted histogram (normalize count as a percentage).
            for ind, array in enumerate(n_shifts):
                weights = 100*np.ones_like(array)/len(array)
                counts, _, _ = plt.hist(np.array(array), bins=bins, weights=weights, edgecolor='black', density=False, alpha=alphas[k%len(alphas)],
                        label=f'{n_txs[ind]} txs, {slip_lims}-{100*within_margin[ind]/len(array):.1f}% | {2*slip_lims}-{100*within_twice_margin[ind]/len(array):.1f}%',
                        color= colors[ind%len(colors)])

                # Getting the values of the first histogram.
                # This will be used to extract the highest count number.
                if ind == 0:
                    values = counts

        if q == len(avg_swap_list) - 1:
            for index, each in enumerate([slip_lims, 2*slip_lims, 3*slip_lims, 4*slip_lims, 5*slip_lims]):
                plt.plot([-each, -each],[0, np.max(values)/2], linestyle='--', linewidth=3, color=slip_colors[index], label=f"{each}% shift", alpha=0.5)
                plt.plot([each, each],[0, np.max(values)/2], linestyle='--', linewidth=3, color=slip_colors[index], alpha=0.8)
    avg_swap_list = np.array(avg_swap_list)
    noise_spread = np.array(noise_spread)
    plt.title(f"Avg. = {avg_swap_list}% | Std. = {noise_spread/(10*NOISE_SPREAD)}% |{n_iterations} it.", fontsize=13)
    plt.xlabel("Slippage Shift", fontsize=13)
    plt.ylabel(" [%] of Total Swaps", fontsize=13)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend()
    plt.show()


def compute_all_shifts(amount_a: float, amount_b: float, avg_swap: float, sigma: float, n_txs: list[float] | NDArray[np.float64], n_iterations: int, slip_lims: float, ):
    """
    Computes all slippage shifts for a number of transactions
     within a transaction thread, for a given number of iterations. Returns a numpy array
     with the all the slippages for the tx thread after n_iterations iterations.
    
     Slippage limits are checkmarks. If a given slippage shift outbursts such limit, this transaction is counted.
    :param amount_a: Amount of tokens A
    :type amount_a: float
    :param amount_b: Amount of tokens B
    :type amount_b: float
    :param avg_swap: Average Swap 
    :type avg_swap: float
    :param sigma: Standard Deviation
    :type sigma: float
    :param n_txs: List of number of Transactions within each batch 
    :type n_txs: list[float] | NDArray[np.float64]
    :param n_iterations: Number of times to iterate for the histogram.
    :type n_iterations: int
    :param slip_lims: Limits of slippage to count. 
    :type slip_lims: float
    """

    # List of slippage transactions which outburst.
    # For each number of transactions provided, in the beginning they all are zero. 
    within_margin = np.zeros_like(n_txs)
    within_twice_margin = np.zeros_like(n_txs)
    long_shifts = []
    n_shifts = []
    n_txs = np.array(n_txs) if type(n_txs) != NDArray[np.float64] else n_txs
    print(type(n_txs))
    if n_txs.any() <= 0:
        raise ValueError("Number of transactions needs to be positive.")
    for index, n_tx in enumerate(n_txs):
                for _ in range(n_iterations):
                    shifts = average_shifts(amount_a, amount_b, n_tx,
                                    avg_swap, sigma, iterations=1,
                                    show=False, index=75, legend=False)
                    long_shifts = np.append(long_shifts, shifts)
                for x in long_shifts:
                    if x > slip_lims or x < -slip_lims:
                        within_margin[index] += 1
                    if x > 2*slip_lims or x < -2*slip_lims:
                        within_twice_margin[index] += 1
                n_shifts.append(long_shifts)
    print(n_shifts)
    print('yo')
    return n_shifts, (within_margin, within_twice_margin)


# Thoughts:

# 1. Extract the worst value given for each tx-id of all the series and plot it?
# 2. Put it with the plot of average
# 3. Put the model on as well (with percentages)
# 4. Do some plots with transaction numbers as sweep
# 5. See the probability of it bursting such ceiling (probability increase)
# 6. It is important to analyze case of bull market, as it will alter significantly the slippage
# even if not the slippage shift. 
# 7. Remember to use stirling approximation to deal with factorials.
# 8. Pass some of these scripts as tests.
# 9. Thoughts on iteration:
#   9.1. Get the total amount of slippages without averaging and histogram it.
# 10. Add/Remove Liquidity transactions
#increase_avg_histograms()
#increase_avg_histograms()
#shifts_by_liquidity()
#increase_number_txs_histograms()
#increase_noise_histograms()
#same_state_cloud(n_times = 1000, n_txs = 1*NUMBER_OF_TXS)
#sweep_transactions(slip_lims=0.1)
sweep_avg_and_std()
#sweep_std(slip_lims=0.15, noise_spread=noise_list)
#sweep_avg_and_std(slip_lims=0.15, noise_spread=noise_list, n_times=1000)
# By liquidity