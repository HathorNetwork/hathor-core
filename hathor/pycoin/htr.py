from pycoin.networks.bitcoinish import create_bitcoinish_network

from hathor.conf import HathorSettings

settings = HathorSettings()

network = create_bitcoinish_network(
    symbol='HTR', network_name='Hathor', subnet_name='mainnet',
    wif_prefix_hex='80',
    address_prefix_hex=settings.P2PKH_VERSION_BYTE.hex(),
    pay_to_script_prefix_hex=settings.MULTISIG_VERSION_BYTE.hex(),
    bip32_prv_prefix_hex='0488ade4', bip32_pub_prefix_hex='0488B21E',
)
