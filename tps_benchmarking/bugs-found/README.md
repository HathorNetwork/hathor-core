# bugs-found

Defects discovered in the upstream `feat/shielded-outputs` branch while bringing shielded outputs into the
TPS benchmark engine. Each is a **self-contained, upstream-ready** write-up (symptom → root cause → why the
existing tests miss it → fix → reproduction). The fixes are carried on our working branch
`tool/tps-bench-shielded` and flagged in the corresponding CP docs (`../checkpoint-diffs/`) so they can be
re-applied if the upstream branch is rebased.

| # | Bug | Component | Severity | Found in | Status |
|---|-----|-----------|----------|----------|--------|
| 1 | [Shielded-output txs fail the Pedersen balance check](bug-shielded-pedersen-balance-not-reconciled.md) — the DAGBuilder assigns each shielded output an independent random value-blinding and never reconciles them, so `verify_shielded_balance` can never hold. | `hathor.dag_builder` (`vertex_exporter.py`) | High | CP‑7 | Fixed on branch |
| 2 | [Shielded txs can't be deserialized from bytes](bug-shielded-deserialize-replace-remaining.md) — `GenericDeserializerAdapter` forwards every read method except `replace_remaining`, so `create_from_struct` → `make_vertex_deserializer().with_max_bytes()` throws on any shielded/unshield/mint/melt header. | `hathorlib.serialization` (`adapters/generic_adapter.py`) | High | CP‑9 | Fixed on branch |
| 3 | [Full-shielded txs with >1 input fail surjection](bug-shielded-surjection-trivial-domain.md) — the builder constructs the surjection proof over a hard-coded single-input domain, but the verifier derives the domain from all inputs, so any FULLY_SHIELDED tx with >1 input is rejected. AMOUNT_ONLY unaffected. | `hathor.dag_builder` (`vertex_exporter.py`) | High | CP‑11 | Root-caused; fix deferred |

## Common thread

Both defects are in code paths the upstream tests never exercise: shielded transactions are only ever built
and **inspected as in-memory objects**, never (1) driven through `verify_shielded_balance`, nor (2)
round-tripped through the byte-parse path used by storage/p2p. Each write-up ends with the specific missing
test that would have caught it.

## Not a bug (kept in `../discussions/`)

- `scoping-wider-confidential-amounts.md` — analysis of the range-proof bit-width limit (why 64 is the
  correct ceiling, and what extending past it would actually require). A design/scoping investigation, not a
  defect.
