#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Service-level differential tests: RustVerificationService.verify_without_storage (one combined Rust
call per vertex) must surface the exact same exception type as the pure-Python VerificationService for
every outcome — including the cases where multiple checks fail and the canonical Python check order
decides which error wins."""

from hathor.conf.get_settings import get_global_settings
from hathor.feature_activation.utils import Features
from hathor.reactor import get_global_reactor
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.verification.rust_verification_service import RustVerificationService
from hathor.verification.script_verification_pool import ScriptVerificationMode, ScriptVerificationPool
from hathor.verification.verification_params import VerificationParams
from hathor.verification.verification_service import VerificationService
from hathor.verification.vertex_verifiers import VertexVerifiers

P2PKH_OUT = bytes.fromhex('76a914a390bb4d6d4ab570767ef21f66c3edc1a4d6902688ac')


def _output(value: int, script: bytes, token_data: int = 0) -> TxOutput:
    """Build a TxOutput bypassing constructor validation: verification must also cover values the
    constructor rejects but a hand-crafted wire vertex could still carry."""
    output = TxOutput(1, script, token_data)
    output.value = value
    return output


def _make_services() -> tuple[dict[str, VerificationService], list[ScriptVerificationPool]]:
    settings = get_global_settings()
    services: dict[str, VerificationService] = {}
    pools: list[ScriptVerificationPool] = []

    def make_verifiers(pool: ScriptVerificationPool | None) -> VertexVerifiers:
        return VertexVerifiers.create_defaults(
            reactor=get_global_reactor(),
            settings=settings,
            daa_factory=None,  # type: ignore[arg-type]  # unused by verify_without_storage
            feature_service=None,  # type: ignore[arg-type]
            tx_storage=None,  # type: ignore[arg-type]
            blueprint_service=None,  # type: ignore[arg-type]
            script_verification_pool=pool,
        )

    services['python'] = VerificationService(settings=settings, verifiers=make_verifiers(None))
    for name, mode in (('rust', ScriptVerificationMode.RUST), ('shadow', ScriptVerificationMode.SHADOW_RUST)):
        pool = ScriptVerificationPool(mode=mode, num_workers=2, min_inputs=1)
        pool.start()
        pools.append(pool)
        services[name] = RustVerificationService(
            settings=settings, verifiers=make_verifiers(pool), script_verification_pool=pool,
        )
    return services, pools


def _make_params() -> VerificationParams:
    return VerificationParams(nc_block_root_id=None, features=Features.all_enabled())


def _set_hash(vertex: Block | Transaction) -> None:
    """Hash the vertex; constructor-invalid outputs (e.g. zero value) cannot even be serialized, so
    those get a synthetic hash — fine here since their weight-0 PoW target (2**256) accepts any hash."""
    try:
        vertex.update_hash()
    except Exception:
        vertex.hash = b'\xab' * 32


def _make_tx(outputs: list[TxOutput], *, tokens: list[bytes] | None = None,
             num_inputs: int = 1, weight: float = 0.0) -> Transaction:
    tx = Transaction(
        timestamp=1000,
        weight=weight,
        inputs=[TxInput(b'\x00' * 32, 0, b'') for _ in range(num_inputs)],
        outputs=outputs,
        tokens=tokens or [],
    )
    _set_hash(tx)
    return tx


def _make_block(outputs: list[TxOutput], *, weight: float = 0.0) -> Block:
    block = Block(timestamp=1000, weight=weight, outputs=outputs)
    _set_hash(block)
    return block


def test_verify_without_storage_equivalence() -> None:
    settings = get_global_settings()
    over_limit_count = settings.MAX_TX_SIGOPS_OUTPUT // 16 + 1
    big_script = b'\x00' * (settings.MAX_OUTPUT_SCRIPT_SIZE + 1)

    vertices: list[tuple[str, Block | Transaction]] = [
        ('tx valid', _make_tx([TxOutput(100, P2PKH_OUT)])),
        ('tx pow fail', _make_tx([TxOutput(100, P2PKH_OUT)], weight=300.0)),
        ('tx too few inputs', _make_tx([TxOutput(100, P2PKH_OUT)], num_inputs=0)),
        # ordering: number-of-inputs (python) fails before outputs (rust) for the same vertex
        ('tx few inputs + bad output', _make_tx([_output(0, b'')], num_inputs=0)),
        ('tx zero value', _make_tx([_output(0, b'\x51')])),
        ('tx hathor authority', _make_tx([TxOutput(1, b'\x51', 0b10000000)])),
        ('tx token index unavailable', _make_tx([TxOutput(1, b'\x51', 1)])),
        ('tx token index ok', _make_tx([TxOutput(1, b'\x51', 1)], tokens=[b'\x01' * 32])),
        ('tx script too large', _make_tx([TxOutput(1, big_script)])),
        ('tx too many outputs', _make_tx([TxOutput(1, b'\x51')] * 256)),
        ('tx sigops over limit', _make_tx([TxOutput(1, b'\x60\xae')] * over_limit_count)),
        ('tx sigops invalid opcode', _make_tx([TxOutput(1, b'\x00')])),
        ('tx sigops truncated push', _make_tx([TxOutput(1, b'\x05\x01')])),
        # ordering: outputs (zero value) fails before sigops (malformed) for the same vertex
        ('tx bad value + bad sigops', _make_tx([_output(0, b'\x00')])),
        # ordering: token index (rust) fails before sigops (rust) — both from the same combined call
        ('tx bad token index + bad sigops', _make_tx([TxOutput(1, b'\x00', 1)])),
        ('block valid', _make_block([TxOutput(6400, P2PKH_OUT)])),
        ('block pow fail', _make_block([TxOutput(6400, P2PKH_OUT)], weight=300.0)),
        ('block hathor authority', _make_block([TxOutput(1, b'\x51', 0b10000000)])),
        ('block sigops invalid opcode', _make_block([TxOutput(1, b'\x00')])),
        ('block zero value', _make_block([_output(0, b'\x51')])),
    ]

    services, pools = _make_services()
    params = _make_params()
    try:
        failures = []
        for label, vertex in vertices:
            outcomes = {}
            for name, service in services.items():
                try:
                    service.verify_without_storage(vertex, params)
                    outcomes[name] = 'valid'
                except BaseException as e:
                    outcomes[name] = type(e).__name__
            if len(set(outcomes.values())) != 1:
                failures.append(f'{label}: {outcomes}')
        assert not failures, 'service outcome mismatches:\n' + '\n'.join(failures)
        for pool in pools:
            assert pool.shadow_mismatches == 0
    finally:
        for pool in pools:
            pool.stop()


def test_rust_service_uses_python_when_pool_not_started() -> None:
    """Before the pool starts (or after it stops), the rust service must fall back to the Python path."""
    settings = get_global_settings()
    pool = ScriptVerificationPool(mode=ScriptVerificationMode.RUST, num_workers=2, min_inputs=1)
    verifiers = VertexVerifiers.create_defaults(
        reactor=get_global_reactor(), settings=settings,
        daa_factory=None, feature_service=None, tx_storage=None,  # type: ignore[arg-type]
        blueprint_service=None,  # type: ignore[arg-type]
        script_verification_pool=pool,
    )
    service = RustVerificationService(settings=settings, verifiers=verifiers, script_verification_pool=pool)
    tx = _make_tx([TxOutput(100, P2PKH_OUT)])
    service.verify_without_storage(tx, _make_params())  # pool not started: python path, must not raise
