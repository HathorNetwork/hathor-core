- Feature Name: peer_whitelist
- Start Date: 2026-04-15
- RFC PR:
- Hathor Issue:
- Feature Spec: docs/p2p/peer-whitelist.md
- Author: Hathor Labs

# Summary
[summary]: #summary

Replace the legacy whitelist mechanism — a flat list on `HathorManager` managed
by the `ENABLE_PEER_WHITELIST` setting and sync-version-dependent blocking logic
— with a self-contained, self-refreshing `PeersWhitelist` subsystem that lives
in the P2P layer, supports URL and file sources, introduces a policy model
(`allow-all` / `only-whitelisted-peers`), and can be reconfigured at runtime via
sysctl.

# Motivation
[motivation]: #motivation

The old whitelist had several problems:

1. **Tangled with sync version logic.** Blocking decisions depended on whether
   the peer was using sync-v1 or sync-v2, controlled by
   `ENABLE_PEER_WHITELIST`, `USE_PEER_WHITELIST_ON_SYNC_V2`, and
   `whitelist_only` — three separate knobs for one concept.
2. **Owned by the wrong layer.** `HathorManager.peers_whitelist` was a plain
   `list[PeerId]` managed at the application layer. The P2P manager fetched and
   diffed the list but delegated add/remove back to `HathorManager`.
3. **No file-based source.** Only a hardcoded URL was supported. Operators in
   airgapped or custom environments had no local alternative.
4. **No runtime reconfiguration.** Changing the whitelist source or
   enabling/disabling it required a node restart.
5. **No grace period.** On startup, the node would connect to arbitrary peers
   before the first whitelist fetch completed.
6. **No backoff on failure.** If the looping call crashed, it restarted after a
   fixed 30 s delay regardless of how many consecutive failures had occurred.
7. **Removal of sync-v1.** With `SyncVersion.V1_1` being dropped, all the
   sync-version-conditional blocking logic becomes dead code.

# Guide-level explanation
[guide-level-explanation]: #guide-level-explanation

## What changed for node operators

A new CLI flag replaces the old implicit behavior:

```
--p2p-whitelist-source <spec>
```

Where `<spec>` is one of:

| Value | Behavior |
|---|---|
| `default` / `hathorlabs` | Use `settings.WHITELIST_URL` (mainnet default). |
| `none` / `disabled` | No whitelist — all peers allowed. |
| A local file path | Read the whitelist from that file. |
| A URL | Fetch from that URL (HTTPS required on mainnet). |

When the flag is omitted, behavior is `default`.

The whitelist content now supports a **policy directive**:

```
hathor-whitelist
policy: allow-all
<peer-id>
<peer-id>
```

This lets the upstream list signal whether it should be enforced or just tracked.

## What changed for developers

- `HathorManager.peers_whitelist` (the old `list[PeerId]`) is removed.
- `HathorManager.add_peer_to_whitelist()` and
  `remove_peer_from_whitelist_and_disconnect()` are removed.
- `ConnectionsManager` now owns a `peers_whitelist: PeersWhitelist | None`
  field that is self-refreshing and self-contained.
- The blocking check in `PeerIdState` is simplified from a multi-branch
  sync-version-aware method to a single delegation:
  `peers_whitelist.is_peer_whitelisted(peer_id)`.
- `SyncVersion.V1_1` and its `is_v1()` helper are removed.
- The `ENABLE_PEER_WHITELIST` setting is removed from mainnet config.
- The `whitelist_only` parameter on `ConnectionsManager` is removed.

## Runtime reconfiguration

Operators can now change the whitelist at runtime via sysctl without restarting:

```
sysctl p2p.connections.whitelist = off      # suspend enforcement
sysctl p2p.connections.whitelist = on       # re-enable
sysctl p2p.connections.whitelist = <url>    # switch source
sysctl p2p.connections.whitelist.status     # inspect state
```

# Reference-level explanation
[reference-level-explanation]: #reference-level-explanation

## New module: `hathor/p2p/whitelist/`

A new package with the following structure:

| File | Responsibility |
|---|---|
| `parsing.py` | `WhitelistPolicy` enum, `parse_whitelist_with_policy()` |
| `peers_whitelist.py` | `PeersWhitelist` ABC — state machine, refresh loop, backoff, admission check |
| `url_whitelist.py` | `URLPeersWhitelist` — HTTP GET with timeout, status check, body parsing |
| `file_whitelist.py` | `FilePeersWhitelist` — threaded file read, same parse/apply flow |
| `factory.py` | `create_peers_whitelist()` — resolves spec string to concrete instance |
| `__init__.py` | Public re-exports |

**Spec impact:**
- Adds RULE-01 through RULE-27: entire feature spec (new feature)
- Adds DEC-01 through DEC-10: all design decisions

## Removed code

### From `HathorManager`

- `peers_whitelist: list[PeerId]` field — replaced by
  `ConnectionsManager.peers_whitelist`.
- `add_peer_to_whitelist()` — the whitelist now manages its own membership.
- `remove_peer_from_whitelist_and_disconnect()` — replaced by
  `_apply_whitelist_update()` which calls the `on_remove_callback`.

### From `ConnectionsManager`

- `whitelist_only: bool` parameter and field — replaced by the policy model
  inside `PeersWhitelist`.
- `update_whitelist()`, `_update_whitelist_cb()`, `_update_whitelist_err()` —
  fetch logic moved to `URLPeersWhitelist._unsafe_update()`.
- `_start_whitelist_reconnect()`, `_handle_whitelist_reconnect_err()` — replaced
  by `PeersWhitelist.start()` and `_handle_refresh_err()` with exponential
  backoff.
- `WHITELIST_REQUEST_TIMEOUT` constant — moved to `url_whitelist.py`.

### From `PeerIdState`

- `_should_block_peer()` — a 20-line method with sync-version branching,
  `ENABLE_PEER_WHITELIST` checks, and `whitelist_only` checks. Replaced by
  `_is_peer_allowed()`: 6 lines, single delegation to
  `peers_whitelist.is_peer_whitelisted()`.

### From `SyncVersion`

- `V1_1 = 'v1.1'` enum member and `is_v1()` method — sync-v1 is no longer
  supported.

### From `hathor/p2p/utils.py`

- `parse_whitelist()` function — replaced by
  `parse_whitelist_with_policy()` in `parsing.py` which also extracts the
  policy directive.

### From settings

- `ENABLE_PEER_WHITELIST` removed from `hathor/conf/mainnet.py`. The whitelist
  is now enabled/disabled by the presence of a `PeersWhitelist` instance, not
  a boolean flag.

## New behavior: grace period

Before the first successful fetch, `is_peer_whitelisted()` only admits peers
registered as bootstrap peers (via `add_bootstrap_peer()`). During
`do_discovery()`, each entrypoint with a peer ID is registered as a bootstrap
peer. This prevents connecting to arbitrary peers during the startup window.

(Spec: RULE-10, RULE-15.2, DEC-01)

## New behavior: exponential backoff

When the refresh looping call crashes (unhandled exception), the restart delay
follows `min(30 * 2^failures, 300)` instead of a fixed 30 s. Resets on success.

(Spec: RULE-12, RULE-13, DEC-06 in the old numbering — now captured as a
constant table in the spec)

## New behavior: file-based whitelist

`FilePeersWhitelist` reads the file in a background thread via
`deferToThread` to avoid blocking the reactor. Handles `FileNotFoundError` and
`PermissionError` gracefully (warn and keep existing list).

(Spec: RULE-21, RULE-22, DEC-04)

## New behavior: policy model

The whitelist file format now supports an optional `policy:` directive. Under
`allow-all`, the list is fetched and tracked but not enforced. This enables
monitoring-only mode and smooth transitions.

(Spec: RULE-06, RULE-07, DEC-07)

## New behavior: sysctl runtime control

`ConnectionsManagerSysctl` exposes `whitelist` (get/set) and
`whitelist.status` (get). The `off`/`on` toggle suspends and restores the
whitelist object without destroying it. Setting a URL or path replaces the
active whitelist entirely.

(Spec: RULE-23, RULE-26, RULE-27, DEC-05, DEC-06)

## Modified: `HelloState`

The `ENABLE_PEER_WHITELIST` guard is removed from the whitelist capability
check. The node now **always** requires the whitelist capability from peers.
The implied sync version for peers without the sync-version capability is
changed from `V1_1` to `V2`.

## Modified: `StatusResource`

`peers_whitelist` in the `/v1a/status` response now reads from
`connections.peers_whitelist.current_whitelist()` instead of
`manager.peers_whitelist`.

(Spec: RULE-25)

## Modified: `Builder`

- `hathor/builder/builder.py`: replaces `whitelist_only=False` with
  `peers_whitelist=self._peers_whitelist`. Adds `set_url_whitelist()` and
  `set_whitelist()` methods.
- `hathor_cli/builder.py`: reads `--p2p-whitelist-source`, defaults to
  `"default"`, calls `create_peers_whitelist()`.

# Drawbacks
[drawbacks]: #drawbacks

- **Breaking change for tooling that reads `HathorManager.peers_whitelist`.**
  Any external code accessing the old `list[PeerId]` field will break. The new
  equivalent is `connections.peers_whitelist.current_whitelist()`.
- **Removes sync-v1 support.** Peers still running sync-v1 will no longer be
  able to connect. This is intentional but narrows compatibility.
- **Centralization pressure unchanged.** The default whitelist URL is still
  controlled by Hathor Labs. This PR does not address that — it only makes the
  source configurable.

# Decisions
[decisions]: #decisions

**D-01: Move whitelist ownership from HathorManager to ConnectionsManager**
Decision: The whitelist is a P2P concern. It belongs in the P2P layer.
Rationale: The old design required `ConnectionsManager` to call back into
`HathorManager` for every add/remove. The new design is self-contained.
Alternative rejected: Keep it on `HathorManager` and add the new features there.
Rejected because it perpetuates the layering violation.

**D-02: Replace boolean flags with a policy enum**
Decision: Use `WhitelistPolicy.ALLOW_ALL` / `ONLY_WHITELISTED_PEERS` instead
of `ENABLE_PEER_WHITELIST` + `USE_PEER_WHITELIST_ON_SYNC_V2` + `whitelist_only`.
Rationale: Three booleans with interacting semantics are hard to reason about.
A single enum with two values is unambiguous.
Alternative rejected: Keep the booleans. Rejected because the interaction matrix
was already a source of bugs.

**D-03: Remove sync-v1 in the same PR**
Decision: Drop `SyncVersion.V1_1` and all sync-version-conditional blocking.
Rationale: Sync-v1 is the reason the old blocking logic was complex. Removing
it simultaneously eliminates dead code paths rather than leaving them for a
follow-up.
Alternative rejected: Remove sync-v1 in a separate PR. Rejected because the
whitelist simplification depends on it — keeping v1 would require preserving the
branching logic.

**D-04: Grace period admits only bootstrap peers, not all peers**
Decision: Before the first successful fetch, only DNS/entrypoint-discovered
peers are allowed.
Rationale: Open admission during grace period defeats the whitelist's purpose
at the most vulnerable moment (startup).
(Spec: DEC-01)

**D-05: Exponential backoff on looping call crash**
Decision: Retry delay follows `min(30 * 2^failures, 300)` instead of fixed 30 s.
Rationale: A crashing loop suggests a persistent issue. Fixed-interval retries
waste resources and can trigger rate limits.
(Spec: RULE-12)

**D-06: File reads in a background thread**
Decision: `FilePeersWhitelist` uses `deferToThread`.
Rationale: Even local reads can block on NFS/slow disks. The reactor must not
stall.
(Spec: DEC-04)

**D-07: Sysctl off/on suspends rather than destroys**
Decision: `off` stores the whitelist object; `on` restores it.
Rationale: Operators need a quick toggle without re-specifying the source.
(Spec: DEC-05)

# Risks & Rollback
[risks-and-rollback]: #risks-and-rollback

- **Risk: nodes on older versions still expect sync-v1.** Mitigation: sync-v1
  has been deprecated and is no longer used on mainnet. Verify no active peers
  are v1-only before deploying.
- **Risk: the grace period blocks all connections if the whitelist URL is
  unreachable at startup and no bootstrap peers are configured.** Mitigation:
  mainnet always has DNS bootstrap. For custom deployments, operators should
  ensure either the whitelist URL is reachable or bootstrap entrypoints include
  peer IDs.
- **Rollback:** revert the PR. The old `ENABLE_PEER_WHITELIST` path will be
  restored. No data migration needed — the whitelist is ephemeral state fetched
  on startup.

# Prior art
[prior-art]: #prior-art

- Bitcoin Core's `-whitelist` flag operates at the IP level. Hathor's approach
  is identity-based (peer IDs derived from public keys), which is stronger
  against IP spoofing.
- Ethereum's `--trustedpeers` is a static list. Hathor's whitelist is
  dynamically refreshed with policy support.

# Testing
[testing]: #testing

- `hathor_tests/p2p/test_whitelist.py` — expanded from the previous whitelist
  tests to cover:
  - Parsing: valid files, policy extraction, invalid headers, invalid peer IDs,
    policy-after-peer-ID error.
  - `URLPeersWhitelist`: successful fetch, HTTP errors, timeout, UTF-8 decode
    failure, non-2xx status.
  - `FilePeersWhitelist`: successful read, file not found, permission denied,
    threaded execution.
  - `PeersWhitelist` base: grace period behavior, bootstrap peer admission,
    re-entrancy guard, exponential backoff calculation, diff/callback on update.
  - Factory: all spec values (`default`, `hathorlabs`, `none`, `disabled`, file
    path, URL), mainnet HTTPS enforcement.
  - Sysctl: on/off toggle, source swap, status reporting.
  - Integration: peer admission during handshake, disconnect on whitelist
    update, status API response.

# Unresolved questions
[unresolved-questions]: #unresolved-questions

- Should the grace period have a timeout after which the node falls back to
  open mode rather than remaining in bootstrap-only mode indefinitely?
- Should `on_remove_callback` be async to allow graceful disconnection
  (e.g. draining in-flight sync)?

# Future possibilities
[future-possibilities]: #future-possibilities

- **Signed whitelists**: cryptographic signature on the response to verify
  the list was published by a trusted authority.
- **Multiple sources**: merge whitelists from several URLs/files to reduce
  single-point-of-failure risk.
- **Per-peer capabilities**: annotate peers in the whitelist with roles
  (e.g., "sync-only", "full").
