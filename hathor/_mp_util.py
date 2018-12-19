"""
This module is an alias to the multiprocessing "spawn" context.

Which would normally be used like:

    from multiprocessing import get_context
    mp = get_context('spawn')
    foo = mp.Process()

This is suboptimal because the user (we) has to call get_context every time, and will scope at most a module-like
object, `mp` in the case above.

When using this module, the following becomes possible:

    from hathor.mp_util import Process
    foo = mp.Process()

That's it. This is the only real purpose of this module.
"""

import sys
import multiprocessing

# `get_context` returns a context object which has the same attributes as the multiprocessing module
# we use this because grpc is not compatible with os.fork (https://github.com/grpc/grpc/issues/13873)
mp = multiprocessing.get_context('spawn')
# mp = multiprocessing.get_context('fork')

del sys.modules['hathor._mp_util']
sys.modules['hathor._mp_util'] = mp
