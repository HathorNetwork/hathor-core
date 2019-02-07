from pycoin.networks.bitcoinish import create_bitcoinish_network

from hathor.constants import MULTISIG_VERSION_BYTE, P2PKH_VERSION_BYTE

network = create_bitcoinish_network(
    symbol='HTR', network_name='Hathor', subnet_name='mainnet',
    wif_prefix_hex='80',
    address_prefix_hex=P2PKH_VERSION_BYTE.hex(),
    pay_to_script_prefix_hex=MULTISIG_VERSION_BYTE.hex(),
    bip32_prv_prefix_hex='0488ade4', bip32_pub_prefix_hex='0488B21E',
)
