from hathor.conf.get_settings import get_global_settings
from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb

from .. import test_blueprints
from .utils import get_ocb_private_key

# XXX: ON_CHAIN_BET_NC_CODE is not imported from test_bet because test_bet will be refactored out
ON_CHAIN_BET_NC_CODE: str = load_builtin_blueprint_for_ocb('bet.py', 'Bet', test_blueprints)


def test_ocb_recompress():
    from hathor.nanocontracts.on_chain_blueprint import Code
    from hathor.transaction.vertex_parser import VertexParser

    # XXX: explicitly compression level to confirm that parsing won't re-compress it, since it can't know the
    #      compression level when decompressing, it must keep the original and thus if it re-compressed it would not
    #      generate the same sequence
    nc_code = ON_CHAIN_BET_NC_CODE
    settings = get_global_settings()
    # XXX: 3 should be more than enough to make a difference from the default (which is 9)
    code = Code.from_python_code(nc_code, settings, compress_level=3)
    code2 = Code.from_python_code(nc_code, settings)
    # but just to make sure, we test it
    assert code.data != code2.data, 'different compression level should yield different results'
    ocb = OnChainBlueprint(
        weight=1,
        inputs=[],
        outputs=[],
        parents=[
            b'\x01' * 32,
            b'\x02' * 32,
        ],
        timestamp=1234,
        code=code,
    )
    ocb.weight = 1.234
    ocb.sign(get_ocb_private_key())
    ocb.update_hash()
    from hathor.transaction.vertex_parser import vertex_serializer
    ocb_bytes = vertex_serializer.serialize(ocb)
    parser = VertexParser(settings=settings)
    ocb2 = parser.deserialize(ocb_bytes)
    assert ocb == ocb2
    ocb_bytes2 = vertex_serializer.serialize(ocb2)
    assert ocb_bytes == ocb_bytes2
