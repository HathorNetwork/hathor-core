from math import floor, sqrt

from hathor.conf import HathorSettings
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.rng import NanoRNG
from hathor.transaction import Transaction
from tests.dag_builder.builder import TestDAGBuilder
from tests.simulation.base import SimulatorTestCase

settings = HathorSettings()


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        x = self.rng.random()
        if x < 0.5:
            raise NCFail('bad luck')


class NCConsensusTestCase(SimulatorTestCase):
    __test__ = True

    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint
        })

        self.manager = self.simulator.create_peer()
        self.manager.tx_storage.nc_catalog = self.catalog

        self.wallet = self.manager.wallet

    def test_rng_consistency(self) -> None:
        seed = self.rng.randbytes(32)
        n = 100_000

        rng1 = NanoRNG(seed=seed)
        v1 = [rng1.randbits(32) for _ in range(n)]
        for _ in range(10):
            rng2 = NanoRNG(seed=seed)
            v2 = [rng2.randbits(32) for _ in range(n)]
            assert v1 == v2

    def assertGoodnessOfFitTest(self, observed: list[int], expected: list[int]) -> None:
        """Pearson chi-square goodness-of-fit test for uniform [0, 1)"""
        assert len(observed) == len(expected)
        size = len(expected)
        N = sum(expected)
        assert N == sum(observed)

        # chi2 = sum((observed[k] - expected[k])**2 / expected[k] for k in range(size))
        # After some algebra, the equation above turns out to be:
        #     chi2 = sum(observed[k]**2 / expected[k] for k in range(size)) - N
        df = 0
        chi2 = 0.
        for k in range(size):
            if expected[k] == 0:
                assert observed[k] == 0
            else:
                chi2 += observed[k]**2 / expected[k]
                df += 1
        chi2 -= N
        df -= 1

        # assumption so we can approximate the chi2 distribution by a normal distribution
        # with mean df and variance 2*df.
        assert df >= 30

        z_score = (chi2 - df) / sqrt(2 * df)
        L = 3

        # The probability of -L < z_score < L is: phi(L) - phi(-L)
        # where phi(x) is the cdf of the standard normal distribution
        # For L = 3, it is 99.73%.
        # In other words, this assert should pass 99.73% of the runs.
        assert -L < z_score < L

    def test_rng_randbits(self) -> None:
        seed = self.rng.randbytes(32)
        rng = NanoRNG(seed=seed)

        size = 4096  # keep it a power of 2
        expected = 100
        frequencies = [0] * size
        for _ in range(expected * size):
            idx = rng.randbits(32) % size
            frequencies[idx] += 1

        self.assertGoodnessOfFitTest(frequencies, [expected] * size)

    def test_rng_randbelow(self) -> None:
        seed = self.rng.randbytes(32)
        rng = NanoRNG(seed=seed)

        size = 10_000
        expected = 100
        frequencies = [0] * size
        for _ in range(expected * size):
            idx = rng.randbelow(size)
            frequencies[idx] += 1

        self.assertGoodnessOfFitTest(frequencies, [expected] * size)

    def test_rng_randint(self) -> None:
        seed = self.rng.randbytes(32)
        rng = NanoRNG(seed=seed)

        size = 10_000
        expected = 100
        frequencies = [0] * size

        a = 150_000
        b = a + size - 1
        for _ in range(expected * size):
            idx = rng.randint(a, b) - a
            frequencies[idx] += 1

        self.assertGoodnessOfFitTest(frequencies, [expected] * size)

    def test_rng_choice(self) -> None:
        seed = self.rng.randbytes(32)
        rng = NanoRNG(seed=seed)

        size = 10_000
        expected = 100
        frequencies = [0] * size

        v = list(range(size))
        for _ in range(expected * size):
            idx = rng.choice(v)
            frequencies[idx] += 1

        self.assertGoodnessOfFitTest(frequencies, [expected] * size)

    def test_rng_randrange_small(self) -> None:
        seed = self.rng.randbytes(32)
        rng = NanoRNG(seed=seed)

        size = 10_000
        expected_per_bin = 500
        frequencies = [0] * size

        start = 15
        stop = size
        step = 7

        valid = set(range(start, stop, step))
        expected = [expected_per_bin if idx in valid else 0 for idx in range(size)]

        for _ in range(expected_per_bin * len(valid)):
            idx = rng.randrange(start, stop, step)
            assert idx in valid
            frequencies[idx] += 1

        self.assertGoodnessOfFitTest(frequencies, expected)

    def test_rng_randrange_large(self) -> None:
        seed = self.rng.randbytes(32)
        rng = NanoRNG(seed=seed)

        size = 1007
        expected = 1000
        frequencies = [0] * size

        start = 15_000_000
        stop = 20_000_000_000
        step = (stop - start + size - 1) // size

        for _ in range(expected * size):
            x = rng.randrange(start, stop, step)
            assert (x - start) % step == 0
            idx = (x - start) // step
            frequencies[idx] += 1

        self.assertGoodnessOfFitTest(frequencies, [expected] * size)

    def test_rng_random(self) -> None:
        seed = self.rng.randbytes(32)
        rng = NanoRNG(seed=seed)

        size = 200
        expected = 1000
        frequencies = [0] * size
        for _ in range(expected * size):
            x = rng.random()
            assert 0 <= x < 1
            idx = floor(size * x)
            frequencies[idx] += 1

        self.assertGoodnessOfFitTest(frequencies, [expected] * size)

    def test_simple_rng(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)

        n = 250
        nc_calls_parts = []
        for i in range(2, n + 2):
            nc_calls_parts.append(f'''
                nc{i}.nc_id = nc1
                nc{i}.nc_method = nop()
                nc{i} --> nc{i-1}
            ''')
        nc_calls = ''.join(nc_calls_parts)

        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..33]
            b30 < dummy

            nc1.nc_id = "{self.myblueprint_id.hex()}"
            nc1.nc_method = initialize()

            {nc_calls}

            nc{n+1} <-- b32
        ''')

        for node, vertex in artifacts.list:
            assert self.manager.on_new_tx(vertex, fails_silently=False)

        nc1, = artifacts.get_typed_vertices(['nc1'], Transaction)
        assert nc1.is_nano_contract()
        assert nc1.get_metadata().voided_by is None

        names = [f'nc{i}' for i in range(2, n + 2)]
        vertices = artifacts.get_typed_vertices(names, Transaction)

        success = 0
        fail = 0
        for v in vertices:
            assert v.is_nano_contract()
            if v.get_metadata().voided_by is None:
                success += 1
            else:
                fail += 1
        self.assertEqual(n, fail + success)

        p = 0.5
        ratio = success / n

        # success ~ Binomial(n=250, p=0.5)
        # For n large, Binomial(n, p) ~ N(n*p, n*p*(1-p))
        # So, ratio ~ N(p, p*(1-p)/n)

        z_score = (ratio - p) / (p * (1 - p) / n)**0.5
        L = 3

        # The probability of -L < z_score < L is: phi(L) - phi(-L)
        # where phi(x) is the cdf of the standard normal distribution
        # For L = 3, it is 99.73%.
        # In other words, this assert should pass 99.73% of the runs.
        assert -L < z_score < L
