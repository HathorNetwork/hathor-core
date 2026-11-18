from matplotlib import pyplot as plt
from scipy.special import gammaln
import numpy as np
from numpy.typing import NDArray

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

def gaussian_curve(avg: float, std_dev: float, x_axis: NDArray[np.float64], plot: bool = False) -> NDArray[np.float64]:
    """
        Creates a theoretical set of points which fits a gaussian distribution. 
    
    :param avg: Average value of the gaussian.
    :type avg: float
    :param std_dev: Standard deviation
    :type std_dev: float
    :param number_of_points: Number of points one wishes to create.
    :type number_of_points: int
    """
    if len(x_axis) <= 0:
        raise Exception(f"Empty x-axis object list.")
    
    if std_dev <= 0:
        raise ValueError(f'Std_deviation {std_dev} must be positive.')
    
    two_p_sqrt = np.sqrt(2*np.pi*std_dev**2)
    arg = (-(x_axis - avg)**2)/(2*std_dev**2)
    exp_to_arg = np.exp(arg)

    # Data points for the theoretical curve
    g_curve = (1/two_p_sqrt)*exp_to_arg

    if plot:
        plt.figure(figsize=(8,6))
        plt.plot(x_axis, g_curve, alpha=0.7, linewidth=2)
        plt.show()

    return g_curve
