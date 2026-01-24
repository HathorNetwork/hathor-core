# Copyright 2025 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Shared fixtures for dry-run tests.

This module provides a common DAG setup that can be used by:
- NCDryRunBlockExecutor tests (detailed validation)
- NCDryRunResource HTTP API tests (serialization validation)
- NcDryRun CLI tests (serialization validation)
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.types import BlueprintId
from hathor.transaction import Block, Transaction

if TYPE_CHECKING:
    from hathor.dag_builder.artifacts import DAGArtifacts
    from hathor.dag_builder.builder import DAGBuilder
    from hathor.manager import HathorManager


class DryRunTestBlueprint(Blueprint):
    """Test blueprint for dry-run tests.

    Provides multiple methods to test different execution scenarios:
    - initialize: Create contract with initial state
    - increment: Modify state (success case)
    - transfer: Modify state with multiple attributes
    - fail_if_negative: Conditional failure based on input
    """
    counter: int
    value: int
    total_calls: int

    @public
    def initialize(self, ctx: Context) -> None:
        """Initialize the contract with default values."""
        self.counter = 0
        self.value = 0
        self.total_calls = 0

    @public
    def increment(self, ctx: Context, amount: int) -> None:
        """Increment value by amount."""
        self.counter += 1
        self.value += amount
        self.total_calls += 1

    @public
    def fail_if_negative(self, ctx: Context, amount: int) -> None:
        """Fail if amount is negative, otherwise increment."""
        if amount < 0:
            raise NCFail('Amount cannot be negative')
        self.value += amount
        self.total_calls += 1


@dataclass
class DryRunDAGFixture:
    """Container for the DAG artifacts and expected results.

    Attributes:
        artifacts: The DAG artifacts from the builder
        blueprint_id: The registered blueprint ID
        block_with_nc: Block containing NC transactions
        block_without_nc: Block without NC transactions
        nc_tx_initialize: The initialize transaction
        nc_tx_increment: The increment transaction
        regular_tx: A regular (non-NC) transaction
        expected_tx_count: Expected number of NC transactions in block_with_nc
    """
    artifacts: 'DAGArtifacts'
    blueprint_id: BlueprintId
    block_with_nc: Block
    block_without_nc: Block
    nc_tx_initialize: Transaction
    nc_tx_increment: Transaction
    regular_tx: Transaction
    expected_tx_count: int = 2


@dataclass
class DryRunExpectedResult:
    """Expected results for detailed validation in executor tests.

    Attributes:
        nc_sorted_calls_count: Expected number of NC transactions
        success_tx_count: Expected number of successful NC transactions
        failure_tx_count: Expected number of failed NC transactions
        skipped_tx_count: Expected number of skipped NC transactions
        root_id_matches: Whether root IDs should match
        expected_methods: List of method names in execution order
        expected_state: Expected final state values {attr: value}
    """
    nc_sorted_calls_count: int = 0
    success_tx_count: int = 0
    failure_tx_count: int = 0
    skipped_tx_count: int = 0
    root_id_matches: bool = True
    expected_methods: list[str] = field(default_factory=list)
    expected_state: dict[str, int] = field(default_factory=dict)


def build_dry_run_dag(
    dag_builder: 'DAGBuilder',
    blueprint_id: BlueprintId,
) -> DryRunDAGFixture:
    """Build a common DAG for dry-run tests.

    Creates a DAG with:
    - 15 blocks in the blockchain
    - 1 contract initialization (tx1)
    - 1 contract method call (tx2)
    - 1 regular non-NC transaction (tx3)
    - Mix of NC and non-NC content in blocks

    The DAG structure:
        genesis -> b1 -> ... -> b10 -> b11 -> b12 -> b13 -> b14 -> b15
                                 |
                                 +-- dummy (funding)

        tx1 (initialize) confirmed in b11
        tx2 (increment) confirmed in b13
        tx3 (regular tx) confirmed in b12

    Args:
        dag_builder: The TestDAGBuilder instance
        blueprint_id: The registered blueprint ID

    Returns:
        DryRunDAGFixture with all artifacts and references
    """
    artifacts = dag_builder.build_from_str(f'''
        blockchain genesis b[1..15]
        b10 < dummy

        # Contract initialization in b11
        tx1.nc_id = "{blueprint_id.hex()}"
        tx1.nc_method = initialize()
        tx1 <-- b11

        # Regular (non-NC) transaction in b12
        dummy < tx3
        tx3 <-- b12

        # Contract method call in b13
        tx2.nc_id = tx1
        tx2.nc_method = increment(42)
        b11 < tx2
        tx2 <-- b13
    ''')

    # Extract typed vertices
    b12, = artifacts.get_typed_vertices(['b12'], Block)
    b13, = artifacts.get_typed_vertices(['b13'], Block)
    tx1, tx2, tx3 = artifacts.get_typed_vertices(['tx1', 'tx2', 'tx3'], Transaction)

    return DryRunDAGFixture(
        artifacts=artifacts,
        blueprint_id=blueprint_id,
        block_with_nc=b13,
        block_without_nc=b12,
        nc_tx_initialize=tx1,
        nc_tx_increment=tx2,
        regular_tx=tx3,
        expected_tx_count=1,  # Only tx2 is in b13
    )


def build_complex_dry_run_dag(
    dag_builder: 'DAGBuilder',
    blueprint_id: BlueprintId,
) -> tuple[DryRunDAGFixture, DryRunExpectedResult]:
    """Build a more complex DAG for detailed executor tests.

    Creates a DAG with multiple method calls including a failure case.

    The DAG structure:
        genesis -> b1 -> ... -> b10 -> b11 -> b12 -> b13 -> b14 -> b15
                                 |
                                 +-- dummy (funding)

        tx1 (initialize) confirmed in b11
        tx2 (increment with 100) confirmed in b12
        tx3 (fail_if_negative with -1) confirmed in b13 - FAILS
        regular_tx (non-NC) confirmed in b14

    Args:
        dag_builder: The TestDAGBuilder instance
        blueprint_id: The registered blueprint ID

    Returns:
        Tuple of (DryRunDAGFixture, DryRunExpectedResult)
    """
    artifacts = dag_builder.build_from_str(f'''
        blockchain genesis b[1..15]
        b10 < dummy

        # Contract initialization in b11
        tx1.nc_id = "{blueprint_id.hex()}"
        tx1.nc_method = initialize()
        tx1 <-- b11

        # Successful increment in b12
        tx2.nc_id = tx1
        tx2.nc_method = increment(100)
        b11 < tx2
        tx2 <-- b12

        # Failed transaction in b13
        tx3.nc_id = tx1
        tx3.nc_method = fail_if_negative(-1)
        tx2 < tx3
        tx3 <-- b13

        # Regular transaction in b14
        dummy < regular_tx
        regular_tx <-- b14
    ''')

    # Extract typed vertices
    b13, b14 = artifacts.get_typed_vertices(['b13', 'b14'], Block)
    tx1, tx2, tx3, regular_tx = artifacts.get_typed_vertices(
        ['tx1', 'tx2', 'tx3', 'regular_tx'], Transaction
    )

    fixture = DryRunDAGFixture(
        artifacts=artifacts,
        blueprint_id=blueprint_id,
        block_with_nc=b13,  # b13 has the failed tx3
        block_without_nc=b14,
        nc_tx_initialize=tx1,
        nc_tx_increment=tx2,
        regular_tx=regular_tx,
        expected_tx_count=1,  # Only tx3 is in b13
    )

    expected = DryRunExpectedResult(
        nc_sorted_calls_count=1,
        success_tx_count=0,
        failure_tx_count=1,  # tx3 fails
        skipped_tx_count=0,
        root_id_matches=True,
        expected_methods=['fail_if_negative'],
        expected_state={'counter': 1, 'value': 100, 'total_calls': 1},
    )

    return fixture, expected


def register_dry_run_blueprint(manager: 'HathorManager') -> BlueprintId:
    """Register the DryRunTestBlueprint with the manager's NC catalog.

    Args:
        manager: The HathorManager instance

    Returns:
        The registered BlueprintId
    """
    blueprint_hex = '3cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e771595'
    blueprint_id = BlueprintId(bytes.fromhex(blueprint_hex))
    nc_catalog = manager.tx_storage.nc_catalog
    assert nc_catalog is not None
    nc_catalog.blueprints[blueprint_id] = DryRunTestBlueprint
    return blueprint_id
