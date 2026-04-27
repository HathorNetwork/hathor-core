# TODOS

## HTR-aware index supply correction for shielded transactions

**Status:** deferred from PR #1664 (`feat/shielded-mint-melt`).

**Context.** `RocksDBTokensIndex` historically tracked transparent visible
supply. PR #1664 chose option (a) — total declared supply (visible +
shielded) — and added cancellation logic for non-HTR tokens involved in
shielded operations: shielding, unshielding, and shielded transfer of a
non-HTR token now leave the index stable. Mint/melt headers contribute
their authoritative amount on top.

The HTR side is intentionally not corrected. The pre-existing parent-branch
behavior remains: HTR shielded amounts are subtracted from the index when
shielded, and added back when unshielded. The index is internally
consistent at the chain level (everything eventually unshields), but
intermediate totals are off by the currently-shielded HTR.

**Why not in PR #1664.** Correct HTR cancellation requires reading:

- `FeeHeader` HTR fees (already on the tx, easy).
- DEPOSIT-version mint deposits and melt withdraws (per `MintHeader` /
  `MeltHeader` entry on a `DEPOSIT` token).
- Per-entry `FEE_PER_OUTPUT` charges (per `MintHeader` / `MeltHeader` entry
  on a `FEE` token).

The DEPOSIT/FEE differentiation needs each header entry's token version,
and `_resolve_token_version_for_mint_melt` in the verifier requires
`nc_block_storage` for nano-issued tokens. The tokens index's `add_tx` /
`remove_tx` is invoked from `IndexesManager.add_to_non_critical_indexes(tx)`
without `nc_block_storage` today, so plumbing is required.

**Approach.**

1. Extend `IndexesManager.add_to_non_critical_indexes` (and
   `remove_from_non_critical_indexes` if separate) to take
   `nc_block_storage`. Update every caller (consensus path).
2. Forward `nc_block_storage` to `RocksDBTokensIndex.add_tx` and
   `remove_tx`.
3. In the index, factor out the HTR-burn computation. Mirror the
   verifier's `_fold_mint_melt_entry` math: sum FeeHeader HTR fees +
   DEPOSIT mint deposits + per-entry FEE charges, subtract DEPOSIT melt
   withdraws. Resolve each entry's token version via
   `_resolve_token_version_for_mint_melt` (extracted into a shared helper
   so the index doesn't reach into the verifier).
4. Apply HTR correction = `−transparent_net_HTR − HTR_burn`. The desired
   `add_to_total(HTR, …)` then equals `−HTR_burn` overall, matching true
   supply change (only fees/deposits actually leave circulation).
5. Tests:
   - HTR shielding without fee.
   - HTR shielding with FeeHeader fee.
   - DEPOSIT-version shielded mint with HTR deposit.
   - DEPOSIT-version shielded melt with HTR withdraw.
   - FEE-version shielded mint with per-entry HTR charge.
   - Reorg symmetry: add then remove returns to baseline for each scenario.

**Estimated cost:** ~50 lines plumbing + ~60 lines index logic + ~80 lines
tests. Single-author follow-up PR. Not user-blocking — explorers and
wallets that rely on `add_to_total` for HTR currently see the
parent-branch transparent-supply semantic, which is consistent with
historical Hathor behavior.

**Why:** ships option (a) consistency for HTR. Without this, HTR totals
oscillate with shielding/unshielding flow, which is correct for transparent
visible supply but inconsistent with the per-token total semantic that
non-HTR tokens now follow.
