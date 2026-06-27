def vertex_decode_encode(data: bytes) -> bytes:
    """Decode a serialized vertex with the Rust codec and re-encode it, returning the bytes.

    Equality with the input proves the Rust codec reads and writes the Python reference's wire
    format faithfully. Raises `ValueError` on malformed input.
    """
    ...

def message_reencode(state: str, line: str) -> str:
    """Parse a single p2p wire line in the given protocol `state` and re-render it via the Rust codec.

    `state` is one of `"hello"`, `"peer-id"`, `"ready"`, or `"any"` (the last accepts every known
    message regardless of state). A line that is malformed or not valid in the requested state
    raises `ValueError`.
    """
    ...

class ProtocolPeer:
    """Scriptable peer driving the real `hathor-next` protocol state machine, sans-IO.

    Python plays the remote peer: `start()` returns the HELLO this peer sends, `feed(line)` advances
    the engine with one inbound wire line and returns the lines it emits in response, and `state`
    reports the current protocol state. This exercises the real handshake and message handling
    without sockets, TLS, or async.
    """

    def __init__(self, network: str) -> None:
        """Build a peer on the named network (`"unittests"`, `"testnet-india"`, `"mainnet"`,
        `"testnet-golf"`, `"testnet-hotel"`). Raises `ValueError` on an unknown network."""
        ...

    @property
    def state(self) -> str:
        """The protocol state: `"hello"`, `"peer-id"`, `"ready"`, or `"closed"`."""
        ...

    def start(self) -> list[str]:
        """Return the outbound HELLO line this peer sends first. Only valid in the HELLO state."""
        ...

    def feed(self, line: str) -> list[str]:
        """Feed one inbound wire line; return the lines the engine emits in response.

        Raises `ValueError` if the line is invalid in the current state (the peer stays usable) or
        if the connection is already closed.
        """
        ...
