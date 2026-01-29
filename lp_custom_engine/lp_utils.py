from matplotlib import pyplot as plt
from scipy.special import gammaln
import numpy as np

def plot_swaps(swaps: list[float]) -> None:
    plt.figure()
    plt.plot(swaps, alpha = 1.0)
    x = np.arange(len(swaps))
    plt.xlabel("Number of Transactions")
    plt.ylabel("Amount Swapped")
    plt.title("Transactions in block")
    plt.grid(True)
    plt.show()


def plot_prices(thread, random: bool = False) -> None:
    plt.figure()
    tx_list = thread.thread

    if random:
        r_prices = [tx.random_price for tx in tx_list]
        plt.plot(r_prices)

    prices = [tx.current_price for tx in tx_list]
    plt.plot(prices, alpha = 1.0)

    plt.xlabel("Number of Transactions")
    plt.ylabel("Price B/A")
    plt.title("Liquidity Pool B/A")
    plt.grid(True)
    plt.show()



def get_slippage(tx_price: float, quoted_price: float) -> float:
    """
        Calculates the slippage seen by a transaction at the moment of purchase.
    """
    slippage = (tx_price/quoted_price - 1)*100
    return slippage

def at_least_k_of_n() -> None:
    """
        Obtains the chance of at least k elements of n being in the set.
        Uses the stirling approximation to minimize computation and allow bigger numbers.
    """
    pass
