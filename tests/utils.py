def create_test_wallet():
    """ Generate a Wallet with a number of keypairs for testing
        :rtype: Wallet
    """
    from hathor.wallet import Wallet, KeyPair
    keys = {}
    for _i in range(20):
        keypair = KeyPair.create(b'MYPASS')
        keys[keypair.address] = keypair
    return Wallet(keys=keys)


def resolve_block_bytes(block_bytes):
    """ From block bytes we create a block and resolve pow
        Return block bytes with hash and nonce after pow
        :rtype: bytes
    """
    from hathor.transaction import Block
    import base64
    block_bytes = base64.b64decode(block_bytes)
    block = Block.create_from_struct(block_bytes)
    block.weight = 10
    block.resolve()
    return block.get_struct()
