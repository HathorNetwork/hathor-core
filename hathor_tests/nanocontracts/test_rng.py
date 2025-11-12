from math import floor, sqrt

import pytest

from hathor.conf import HathorSettings
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.faux_immutable import create_with_shell
from hathor.nanocontracts.rng import NanoRNG
from hathor.nanocontracts.types import ContractId
from hathor.transaction import Transaction
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.simulation.base import SimulatorTestCase

settings = HathorSettings()


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        x = self.syscall.rng.random()
        if x < 0.5:
            raise NCFail('bad luck')


class AttackerBlueprint(Blueprint):
    target: ContractId

    @public
    def initialize(self, ctx: Context, target: ContractId) -> None:
        self.target = target

    @public
    def attack(self, ctx: Context) -> None:
        self.syscall.rng.random = lambda: 0.75  # type: ignore[method-assign]
        self.syscall.get_contract(self.target, blueprint_id=None).public().nop()


class NCConsensusTestCase(SimulatorTestCase):
    __test__ = True

    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.attacker_blueprint_id = b'y' * 32
        self.catalog = NCBlueprintCatalog({
            self.myblueprint_id: MyBlueprint,
            self.attacker_blueprint_id: AttackerBlueprint,
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

    def test_rng_override(self) -> None:
        seed = b'0' * 32
        rng = NanoRNG(seed=seed)

        #
        # Existing attribute on instance
        #

        # protected by overridden __setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `_NanoRNG__seed` on faux-immutable object'):
            rng._NanoRNG__seed = b'1' * 32

        # protected by overridden __setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `_NanoRNG__seed` on faux-immutable object'):
            setattr(rng, '_NanoRNG__seed', b'1' * 32)

        # it doesn't protect against this case
        object.__setattr__(rng, '_NanoRNG__seed', b'changed')
        assert getattr(rng, '_NanoRNG__seed') == b'changed'

        #
        # New attribute on instance
        #

        # protected by overridden NanoRNG.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `new_attr` on faux-immutable object'):
            rng.new_attr = 123

        # protected by overridden NanoRNG.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `new_attr` on faux-immutable object'):
            setattr(rng, 'new_attr', 123)

        # protected by __slots__
        with pytest.raises(AttributeError, match="'NanoRNG' object has no attribute 'new_attr'"):
            object.__setattr__(rng, 'new_attr', 123)

        #
        # Existing method on instance
        #

        # protected by overridden NanoRNG.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable object'):
            rng.random = lambda self: 2  # type: ignore[method-assign, misc, assignment]

        # protected by overridden NanoRNG.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable object'):
            setattr(rng, 'random', lambda self: 2)

        # protected by overridden NanoRNG.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable object'):
            from types import MethodType
            rng.random = MethodType(lambda self: 2, rng)  # type: ignore[method-assign]

        # protected by __slots__
        with pytest.raises(AttributeError, match='\'NanoRNG\' object attribute \'random\' is read-only'):
            object.__setattr__(rng, 'random', lambda self: 2)

        #
        # Existing method on class
        #

        # protected by overridden NoMethodOverrideMeta.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable class'):
            NanoRNG.random = lambda self: 2  # type: ignore[method-assign]

        # protected by overridden NoMethodOverrideMeta.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable class'):
            setattr(NanoRNG, 'random', lambda self: 2)

        # protected by Python itself
        with pytest.raises(TypeError, match='can\'t apply this __setattr__ to FauxImmutableMeta object'):
            object.__setattr__(NanoRNG, 'random', lambda self: 2)

        #
        # Existing method on __class__
        #

        # protected by overridden NoMethodOverrideMeta.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable class'):
            rng.__class__.random = lambda self: 2  # type: ignore[method-assign]

        # protected by overridden NoMethodOverrideMeta.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable class'):
            setattr(rng.__class__, 'random', lambda self: 2)

        # protected by Python itself
        with pytest.raises(TypeError, match='can\'t apply this __setattr__ to FauxImmutableMeta object'):
            object.__setattr__(rng.__class__, 'random', lambda self: 2)

        #
        # New attribute on class
        #

        # protected by overridden NoMethodOverrideMeta.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `new_attr` on faux-immutable class'):
            NanoRNG.new_attr = 123

        # protected by overridden NoMethodOverrideMeta.__setattr__
        with pytest.raises(AttributeError, match='cannot set attribute `new_attr` on faux-immutable class'):
            setattr(NanoRNG, 'new_attr', 123)

        # protected by Python itself
        with pytest.raises(TypeError, match='can\'t apply this __setattr__ to FauxImmutableMeta object'):
            object.__setattr__(NanoRNG, 'new_attr', 123)

        assert rng.random() < 1

    def test_rng_shell_class(self) -> None:
        seed = b'0' * 32
        rng1 = create_with_shell(NanoRNG, seed=seed)
        rng2 = create_with_shell(NanoRNG, seed=seed)

        assert rng1.__class__ != rng2.__class__

        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable class'):
            rng1.__class__.random = lambda self: 2  # type: ignore[method-assign]

        with pytest.raises(AttributeError, match='cannot set attribute `random` on faux-immutable class'):
            setattr(rng1.__class__, 'random', lambda self: 2)

        with pytest.raises(TypeError, match='can\'t apply this __setattr__ to FauxImmutableMeta object'):
            object.__setattr__(rng1.__class__, 'random', lambda self: 2)

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
            assert self.manager.on_new_tx(vertex)

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

    def test_attack(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)

        n = 250
        nc_calls_parts = []
        for i in range(3, n + 3):
            nc_calls_parts.append(f'''
                nc{i}.nc_id = nc2
                nc{i}.nc_method = attack()
                nc{i} --> nc{i-1}
            ''')
        nc_calls = ''.join(nc_calls_parts)

        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..33]
            b30 < dummy

            nc1.nc_id = "{self.myblueprint_id.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = "{self.attacker_blueprint_id.hex()}"
            nc2.nc_method = initialize(`nc1`)
            nc2 --> nc1

            {nc_calls}

            nc{n+2} <-- b32
        ''')

        for node, vertex in artifacts.list:
            assert self.manager.on_new_tx(vertex)

        nc1, = artifacts.get_typed_vertices(['nc1'], Transaction)
        assert nc1.is_nano_contract()
        assert nc1.get_metadata().voided_by is None

        names = [f'nc{i}' for i in range(3, n + 3)]
        vertices = artifacts.get_typed_vertices(names, Transaction)

        success = 0
        fail = 0
        for v in vertices:
            assert v.is_nano_contract()
            assert v.get_metadata().nc_execution is not None
            if v.get_metadata().voided_by is None:
                success += 1
            else:
                fail += 1
        self.assertEqual(0, success)
        self.assertEqual(n, fail)
