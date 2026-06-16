# Defect report — shielded txs cannot be deserialized from bytes (`replace_remaining` not forwarded)

> Standalone bug write-up (companion to `checkpoint-diffs/CP-9-shielded-workload-and-cli.md`, which records
> the same finding as part of our work). Self-contained so it can be filed upstream on its own. This is the
> **second** independent defect we hit in the shielded-outputs feature; the first is
> `bug-shielded-pedersen-balance-not-reconciled.md`.

| | |
|---|---|
| **Component** | `hathorlib.serialization` (deserializer adapters) + the vertex parse path |
| **Branch** | `feat/shielded-outputs` (origin/HathorNetwork), tip `5ebfe178` |
| **Severity** | High — a transaction carrying a shielded / unshield / mint / melt header **cannot be parsed from bytes** via the standard `create_from_struct` path. That path is used to load vertices from storage and from the p2p wire, so shielded txs are effectively un-relayable / un-loadable as serialized bytes. |
| **Status** | Root-caused and fixed on our benchmark branch `tool/tps-bench-shielded` (one-method forward, §4). |

---

## 1. Symptom

Deserializing a shielded-output transaction from its serialized bytes raises:

```
TypeError: this deserializer does not support replace_remaining
```

Traceback (abridged):
```
Transaction.create_from_struct(struct_bytes)
  -> deserialize_headers(deserializer, tx, settings)            # hathor/transaction/vertex_parser/_headers.py:70
     -> deserializer.replace_remaining(leftover)
        -> Deserializer.replace_remaining                       # hathorlib/.../deserializer.py:98
           raise TypeError('this deserializer does not support replace_remaining')
```

This reproduces for any vertex with a `ShieldedOutputsHeader`, `UnshieldBalanceHeader`, `MintHeader`, or
`MeltHeader` — all of which use the same read-all / push-back-leftover parse pattern.

## 2. Root cause

The header parser for these headers reads all remaining bytes, parses one header, and pushes the unconsumed
tail back via `deserializer.replace_remaining(leftover)` (`hathor/transaction/vertex_parser/_headers.py:66-70`):

```python
remaining_bytes = bytes(deserializer.read_all())
shielded_header, leftover = ShieldedOutputsHeader.deserialize(vertex, remaining_bytes)
deserializer.replace_remaining(leftover)        # <-- requires replace_remaining
```

`replace_remaining` is supported by **`BytesDeserializer`**
(`hathorlib/serialization/bytes_deserializer.py:78`). But `create_from_struct` does **not** use a bare
`BytesDeserializer` — it wraps it:

```python
# hathor/transaction/transaction.py:121
deserializer = make_vertex_deserializer(struct_bytes, settings)
# hathor/transaction/vertex_parser/_common.py:
#   return Deserializer.build_bytes_deserializer(struct_bytes).with_max_bytes(max_size)
```

`.with_max_bytes(...)` returns a **`MaxBytesDeserializer`**, a `GenericDeserializerAdapter`
(`hathorlib/serialization/adapters/generic_adapter.py`). That adapter forwards `read_byte`, `read_bytes`,
`read_all`, `peek_byte`, `peek_bytes`, `finalize`, `is_empty` to the inner deserializer — **but it does not
forward `replace_remaining`.** So the call resolves to the base `Deserializer.replace_remaining`, which raises.

## 3. Why upstream never caught it

Same shape as the balance bug: shielded txs are only ever exercised as **in-memory objects built by the
DAGBuilder**, never round-tripped through the byte-parse path used in production.

- `test_shielded_dag_builder.py` builds objects and inspects them; it never calls `create_from_struct` on
  full shielded tx bytes.
- `test_header_serialization_roundtrip` deserializes a header **in isolation** using a bare
  `BytesDeserializer` (which *does* support `replace_remaining`) — not through
  `make_vertex_deserializer().with_max_bytes()`.
- No test parses a full shielded *transaction* from bytes through the wrapped deserializer that production
  uses, so the missing forward is never hit.

## 4. The fix

Forward `replace_remaining` in the adapter, exactly like the other read methods
(`hathorlib/serialization/adapters/generic_adapter.py`):

```python
@override
def replace_remaining(self, data: Buffer) -> None:
    self.inner.replace_remaining(data)
```

This fixes it for `MaxBytesDeserializer` and any other `GenericDeserializerAdapter`. (The `MaxBytesDeserializer`
byte budget stays consistent: its `read_all` reads the inner remainder without decrementing the counter, so
pushing a small `leftover` back and continuing to read the next header does not trip `MaxBytesExceededError`.)

## 5. Reproduction

```python
# Build a shielded-output tx with the DAGBuilder (manager with ENABLE_SHIELDED_TRANSACTIONS enabled),
# serialize it, then parse it back from bytes:
raw = bytes(tx1)                                  # tx1 has 2 [shielded] outputs
manager.vertex_parser.deserialize(raw)            # -> create_from_struct -> TypeError before the fix
```
Before the fix: `TypeError: this deserializer does not support replace_remaining`.
After the fix: parses successfully (round-trips).

(In our engine this is exercised by the driver's **S1** stage, which re-parses each tx's bytes to time
deserialization; it was the first thing to drive shielded txs through the byte-parse path.)

## 6. Suggested upstream follow-ups

1. Add the `replace_remaining` forward to `GenericDeserializerAdapter` (§4).
2. Add a test that serializes a full shielded / unshield / mint / melt **transaction** and parses it back via
   `vertex_parser.deserialize` / `create_from_struct` (asserting equality) — the missing byte-round-trip
   coverage that hid this.
