Multiprocess
============

.. TODO: process architecture diagram

Current architecture:

* Main Process (HathorManager + TransactionStorage + \*Resources)
* Wallet Process (Wallet + WallteResources)
* Validator Process (Validator)

.. TODO: elaborate more

Processes talk to each other via GRPC, which is basically Protobuf over HTTP2.

Main process spawns other processes.

GRPC's Python implementation is not compatible with using fork for spawning a subprocess, so the 'spawn' implementation
(instead of 'fork') must be explicily selected.

To support multiple "instances" of Hathor running on the same host, and avoid fs locks as much as possible, the ports
GRPC will bind to are random (which is the default), thus, the ports need to be known beforehand for creating the
client factory classes.

Client factory classes are a function like picklable classes whose instances return an instance of a client that
internally uses GRPC to communicate with the servicer.

.. TODO: examples


Currently, a noticeable downside of our approach is the high amount of boilerplate. This can be potentially sovled, or
at least lessened by metaprogramming and code generation. Though the trade-offs aren't too clear yet.
