""" It measures the number of operations per second involving digital signatures.
"""

import timeit

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

number = 20000

dt = timeit.timeit('ec.generate_private_key(ec.SECP256K1(), default_backend())', number=number, globals=globals())
print('Private key generations per second: {:.1f}'.format(number / dt))

data = bytes(32)
priv_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
dt = timeit.timeit('priv_key.sign(data, ec.ECDSA(hashes.SHA256()))', number=number, globals=globals())
print('Generation of digital signatures per second: {:.1f}'.format(number / dt))

pub_key = priv_key.public_key()
signature = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
dt = timeit.timeit('pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))', number=number, globals=globals())
print('Verification of digital signatures per second: {:.1f}'.format(number / dt))
