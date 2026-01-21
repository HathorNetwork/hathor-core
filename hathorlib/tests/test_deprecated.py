import pytest

from hathorlib.base_transaction import tx_or_block_from_bytes
from hathorlib.nanocontracts import DeprecatedNanoContract


@pytest.mark.parametrize(
    ['hex_hash', 'hex_bytes'],
    [
        # Without actions
        (
            '000081fc23f06c2e0198e92d88bae373b9291281eaa1bde70a25895e8f395ebe',
            '0004000000013cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e7715950a696e697469616c697a650024001'
            '976a9145f6557d55ebd9b9f17ac6d3dec9e62c3983e0f9d88ac000100000467d3162d21038125cdd1ba7942439d1cca8a622ce046'
            'ba94549375f8125b166a4c9f9545a9044730450221009ce1c5bd1f53a3123bbce623fb3ce54460814bb8fba7bee3a2d147a6d32e0'
            'd87022066857e268dd8e84272543ab3e5ba9e8389155be5f289116df07e76a1204f33e24030f50e7c7b57cb67d308ce0200000744'
            '71704d198d5ebcfa31bc281d69a1d900c0c197444386d7bdf5db13c4000016cfc9ea80a9faebd599af3eb1a6c50308e2c74e003c4'
            'a502b9bddbf639400ff68b3',
        ),

        # With actions
        (
            '0000540ff09eff4811932fd954f7e070c37a36428d73c931af243eff43bb970b',
            '00040000010000012c00001976a9145f6557d55ebd9b9f17ac6d3dec9e62c3983e0f9d88ac010000049be6b42e863d93c304519e6'
            'fa2e1731529b0ca3958b1a2f36c869fbd5c087769746864726177000021038125cdd1ba7942439d1cca8a622ce046ba94549375f8'
            '125b166a4c9f9545a9044730450221009d12fc897c1a78658c8448f0c5b733f8f0019c079c51ab5d0f1804f58a9f128502202d16b'
            '85ae939d2d8e023dec0f466aa3cf62c4839ed1a82d54f191ac516bf21e9403105b214e1b93767db0afb02000026ff3dd377bfab1e'
            '643caa5bc4b51981cead3a53389610f8b3eb6df89c300000006f1d0156981bc023f2e99c1d3ee653418ff2a2da5a187d07d8a7dfe'
            '26900fbcd09'
        )
    ]
)
def test_deprecated_nano_contract(hex_bytes: str, hex_hash: str) -> None:
    tx_bytes = bytes.fromhex(hex_bytes)
    expected_tx_hash = bytes.fromhex(hex_hash)

    tx = tx_or_block_from_bytes(tx_bytes)
    assert isinstance(tx, DeprecatedNanoContract)
    assert tx.hash == expected_tx_hash
    assert bytes(tx) == tx_bytes
