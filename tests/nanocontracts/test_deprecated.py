from hathor.conf.get_settings import _load_yaml_settings


def test_deprecated_nano_contract():
    settings = _load_yaml_settings('hathor/conf/nano_testnet.yml')

    tx_bytes = bytes.fromhex('0004000000013cb032600bdf7db784800e4ea911b10676fa2f67591f82bb62628c234e7715950a696e697'
                             '469616c697a650024001976a9145f6557d55ebd9b9f17ac6d3dec9e62c3983e0f9d88ac000100000467d3'
                             '162d21038125cdd1ba7942439d1cca8a622ce046ba94549375f8125b166a4c9f9545a9044730450221009'
                             'ce1c5bd1f53a3123bbce623fb3ce54460814bb8fba7bee3a2d147a6d32e0d87022066857e268dd8e84272'
                             '543ab3e5ba9e8389155be5f289116df07e76a1204f33e24030f50e7c7b57cb67d308ce020000074471704'
                             'd198d5ebcfa31bc281d69a1d900c0c197444386d7bdf5db13c4000016cfc9ea80a9faebd599af3eb1a6c5'
                             '0308e2c74e003c4a502b9bddbf639400ff68b3')

    expected_tx_hash = bytes.fromhex('000081fc23f06c2e0198e92d88bae373b9291281eaa1bde70a25895e8f395ebe')

    from hathor.nanocontracts.nanocontract import DeprecatedNanoContract
    from hathor.transaction.vertex_parser import VertexParser
    from hathor.verification.nano_contract_verifier import NanoContractVerifier

    vertex_parser = VertexParser(settings=settings)
    tx = vertex_parser.deserialize(tx_bytes)
    assert isinstance(tx, DeprecatedNanoContract)
    assert tx.hash == expected_tx_hash
    assert bytes(tx) == tx_bytes

    nc_verifier = NanoContractVerifier()
    nc_verifier.verify_nc_signature(tx)
