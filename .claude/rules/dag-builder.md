---
globs: ["hathor_tests/**/*.py", "hathor/dag_builder/**/*.py"]
---

# DAGBuilder

## DSL Syntax Reference

The `build_from_str()` method accepts a string-based DSL for building DAG structures:

```
blockchain genesis b[1..50]          # create chain of 50 blocks from genesis
a <-- b <-- c                        # parent edges (left is child, right is parent for <--)
a --> b --> c                         # parent edges (left is parent, right is child for -->)
a.out[0] <<< b c d                   # spending edges (b, c, d spend output 0 of a)
b30 < dummy                          # ordering dependency (dummy created before b30)
a.out[0] = 100 HTR                   # set output amount and token
a.out[1] = 100 TKA                   # custom token (auto-creates TokenCreationTransaction)
a.weight = 31.8                      # set vertex weight
```

## Nano Contract Attributes

```
tx.nc_id = "{hex}"                   # nano contract ID (hex string)
tx.nc_id = other_tx                  # nano contract ID from another vertex
tx.nc_method = initialize()          # method call with no args
tx.nc_method = deposit(arg1, arg2)   # method call with args
tx.nc_deposit = 10 HTR               # deposit tokens into contract
tx.nc_withdrawal = 5 TKA             # withdraw tokens from contract
```

## On-Chain Blueprint Attributes

```
ocb.ocb_private_key = "{hex}"        # signing key
ocb.ocb_password = "{hex}"           # password
ocb.ocb_code = "{hex}"               # hex-encoded code
ocb.ocb_code = file.py, ClassName    # code from file
```

## Fee-Based Token Attributes

```
FBT.token_version = fee              # mark as fee-based token
FBT.fee = 1 HTR                      # set fee amount
```

## Initialization Pattern

```python
from hathor_tests.dag_builder.builder import TestDAGBuilder

# In setUp:
builder = self.get_builder()
self.manager = self.create_peer_from_builder(builder)
self.dag_builder = TestDAGBuilder.from_manager(self.manager)
```

## Build & Propagate

```python
artifacts = self.dag_builder.build_from_str('''
    blockchain genesis b[1..50]
    b1.out[0] <<< tx1
    b30 < tx1
    b40 --> tx1
''')
artifacts.propagate_with(self.manager)

# Retrieve vertices
tx1 = artifacts.get_typed_vertex('tx1', Transaction)
b1, b40 = artifacts.get_typed_vertices(['b1', 'b40'], Block)
```

## Partial Propagation

```python
artifacts.propagate_with(self.manager, up_to='b10')        # propagate up to b10
artifacts.propagate_with(self.manager, up_to_before='tx1')  # stop before tx1
artifacts.propagate_with(self.manager)                      # finish remaining
```

## Key Rules

- Always include `b{N} < dummy` where N >= REWARD_SPEND_MIN_BLOCKS to unlock block rewards
- Custom tokens (TKA, TKB, etc.) auto-create TokenCreationTransaction vertices
- Node names are unique identifiers — same name always refers to the same vertex
- Blocks cannot have inputs; transactions cannot be block parents
- DefaultFiller auto-fills missing parents, outputs, and balances

## Key Files

- Implementation: `hathor/dag_builder/builder.py`, `tokenizer.py`, `default_filler.py`, `artifacts.py`
- Test helper: `hathor_tests/dag_builder/builder.py` (TestDAGBuilder)
- Examples: `hathor_tests/dag_builder/test_dag_builder.py`
