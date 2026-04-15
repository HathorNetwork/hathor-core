- Feature Name: peer_whitelist
- Status: Implemented
- Start Date: 2026-04-15
- Authors: Hathor Labs
- Hathor Issue:
- Implementation PR(s):

# Overview

A peer whitelist mechanism for the P2P layer that restricts which peers a node
may connect to. The whitelist is fetched from a remote URL or read from a local
file, refreshed periodically, and supports two policies: `only-whitelisted-peers`
(default) and `allow-all`. It can be reconfigured at runtime via sysctl.

# Specification

## Configuration

### CLI

The whitelist is configured via a single CLI argument:

```
--p2p-whitelist-source <spec>
```

**RULE-01**: When `--p2p-whitelist-source` is omitted, the node MUST behave as
if `default` was passed.

**RULE-02**: The `<spec>` value MUST be resolved in the following order:

| `<spec>` value (case-insensitive) | Resolution |
|---|---|
| `default` or `hathorlabs` | Use `settings.WHITELIST_URL`. If `WHITELIST_URL` is `None`, the whitelist MUST be disabled (treated as `None`). |
| `none` or `disabled` | Whitelist MUST be disabled — all peers allowed. |
| An existing local file path | Use file-based whitelist reading from that path. |
| Anything else | Treat as a URL. On mainnet, the URL MUST use the `https` scheme and MUST have a non-empty netloc; otherwise construction MUST raise `ValueError`. |

### Constants

| Constant | Value | Purpose |
|---|---|---|
| `WHITELIST_REFRESH_INTERVAL` | 30 s | Interval for the periodic refresh looping call. |
| `WHITELIST_RETRY_INTERVAL_MIN` | 30 s | Base interval for exponential backoff on looping call crash. |
| `WHITELIST_RETRY_INTERVAL_MAX` | 300 s | Cap for exponential backoff. |
| `WHITELIST_REQUEST_TIMEOUT` | 45 s | HTTP request timeout for URL-based whitelist. |

## Data format

**RULE-03**: Whitelist content (whether served over HTTP or read from a file)
MUST conform to this format:

```
hathor-whitelist
# Optional comment
policy: <policy-type>
<peer-id-hex>
<peer-id-hex>
...
```

**RULE-04**: The first line MUST be the literal string `hathor-whitelist`. If
the header does not match, parsing MUST raise `ValueError`.

**RULE-05**: Lines starting with `#` MUST be treated as comments and ignored.
Blank lines (empty or whitespace-only after stripping) MUST be ignored.

**RULE-06**: The `policy:` directive is optional. If present, it MUST appear
before any peer ID lines. If a `policy:` line appears after a peer ID line,
parsing MUST raise `ValueError`.

**RULE-07**: Valid policy values are:

| Policy value | Behavior |
|---|---|
| `only-whitelisted-peers` | Only peers in the list are accepted. This is the default when no `policy:` line is present. |
| `allow-all` | All peers are accepted regardless of list membership. |

Any other policy value MUST raise `ValueError`.

**RULE-08**: Each non-comment, non-policy, non-blank line MUST be parsed as a
hex-encoded peer ID (first whitespace-delimited token). Invalid peer IDs MUST
be skipped with a warning log — they MUST NOT cause the entire parse to fail.

## Lifecycle

The whitelist has three operational states:

| State | `peers_whitelist` field | `_has_successful_fetch` | Description |
|---|---|---|---|
| GRACE_PERIOD | set (non-None) | `False` | Whitelist exists but no successful fetch yet. Only bootstrap peers allowed. |
| ENFORCING | set (non-None) | `True` | Whitelist loaded. Policy is applied to all peer checks. |
| DISABLED | `None` | N/A | No whitelist configured. All peers allowed. |

State transitions:

| Current state | Event | Next state | Side effects |
|---|---|---|---|
| GRACE_PERIOD | Fetch succeeds | ENFORCING | Apply whitelist, reset backoff. |
| GRACE_PERIOD | Fetch fails | GRACE_PERIOD | Increment backoff counter. Keep bootstrap-only mode. |
| ENFORCING | Fetch succeeds | ENFORCING | Apply new whitelist (diff, disconnect removed peers), reset backoff. |
| ENFORCING | Fetch fails | ENFORCING | Increment backoff counter. Keep previous whitelist. |
| ENFORCING | sysctl `off` | DISABLED (suspended) | Whitelist object stored in `_suspended_whitelist`. Active set to `None`. |
| DISABLED (suspended) | sysctl `on` | ENFORCING | Restore `_suspended_whitelist` as active. Disconnect non-whitelisted peers. |
| DISABLED | sysctl set URL/path | GRACE_PERIOD → ENFORCING | Create new whitelist, start refresh loop. |

### Startup sequence

**RULE-09**: On `ConnectionsManager.start()`, if `peers_whitelist` is not
`None`, the manager MUST call `whitelist.start(self.drop_connection_by_peer_id)`
which starts the periodic refresh looping call.

**RULE-10**: During `do_discovery()`, for each discovered entrypoint that has a
non-None `peer_id`, the manager MUST call
`whitelist.add_bootstrap_peer(peer_id)`. This seeds the grace-period allowlist
so the node can connect to bootstrap peers before the first fetch completes.

### Periodic refresh

**RULE-11**: The refresh looping call MUST fire every `WHITELIST_REFRESH_INTERVAL`
(30 s). Each invocation calls `update()`, which is re-entrancy-guarded: if an
update is already running, the call MUST be skipped with a warning log.

**RULE-12**: If `update()` (specifically `_unsafe_update()`) raises an unhandled
exception that kills the looping call, `_handle_refresh_err` MUST restart the
loop after a delay computed by exponential backoff:

```
interval = min(WHITELIST_RETRY_INTERVAL_MIN * 2^consecutive_failures, WHITELIST_RETRY_INTERVAL_MAX)
```

| Consecutive failures | Retry interval |
|---|---|
| 0 | 30 s |
| 1 | 60 s |
| 2 | 120 s |
| 3+ | 300 s (cap) |

**RULE-13**: On a successful update, the backoff counter (`_consecutive_failures`)
MUST reset to 0.

### Shutdown

**RULE-14**: On `ConnectionsManager.stop()`, if `peers_whitelist` is not `None`,
the manager MUST call `whitelist.stop()`, which cancels any pending retry
(`_pending_retry`) and stops the looping call if running.

## Behavior

### Peer admission check

**RULE-15**: The whitelist check occurs during the `PEER-ID` handshake state,
after the remote peer sends its identity. The check logic is:

1. If `connections.peers_whitelist` is `None` → peer is **allowed**.
2. If `_has_successful_fetch` is `False` (grace period) → peer is allowed
   **only if** `peer_id in _bootstrap_peers`.
3. If `_policy` is `ALLOW_ALL` → peer is **allowed**.
4. If `_policy` is `ONLY_WHITELISTED_PEERS` → peer is allowed **only if**
   `peer_id in _current`.

**RULE-16**: When a peer is rejected and `settings.WHITELIST_WARN_BLOCKED_PEERS`
is `True`, the error message MUST include the blocked peer's ID:
`"Blocked (by {peer_id}). Get in touch with Hathor team."`.
Otherwise, the message MUST be the generic `"Connection rejected."`.

### Whitelist update application

**RULE-17**: When a new whitelist is successfully parsed, `_apply_whitelist_update`
MUST:

1. Compute the diff between the old and new peer sets.
2. Log additions and removals.
3. For each removed peer, call `_on_remove_callback(peer_id)` if the callback
   is set. The callback (`drop_connection_by_peer_id`) disconnects the peer.
4. Replace `_current` with the new set.
5. Replace `_policy` with the new policy.
6. Set `_has_successful_fetch = True`.
7. Call `_on_update_success()` to reset the backoff counter.

**RULE-18**: On fetch failure (network error, non-2xx HTTP status, parse error),
the existing `_current` and `_policy` MUST be preserved. The failure MUST
increment `_consecutive_failures` via `_on_update_failure()`.

### URL-based whitelist specifics

**RULE-19**: `URLPeersWhitelist._unsafe_update()` MUST:

1. If `_url` is `None`, return immediately (no-op, resolved deferred).
2. Issue an HTTP GET with header `User-Agent: hathor-core`.
3. Validate HTTP status is 2xx; reject otherwise with `ValueError`.
4. Read the full response body.
5. Apply a `WHITELIST_REQUEST_TIMEOUT` (45 s) timeout on the entire operation.
6. Decode the body as UTF-8.
7. Parse via `parse_whitelist_with_policy()`.
8. On success: call `_apply_whitelist_update()`. On any failure: call
   `_on_update_failure()`.

**RULE-20**: If the URL constructor receives the string `"none"`
(case-insensitive), it MUST normalize `_url` to `None`, effectively disabling
fetches.

### File-based whitelist specifics

**RULE-21**: `FilePeersWhitelist._unsafe_update()` MUST read the file in a
background thread (`deferToThread`) to avoid blocking the reactor.

**RULE-22**: On `FileNotFoundError` or `PermissionError`, the file whitelist
MUST log a warning and keep the existing whitelist (call `_on_update_failure()`
but do not clear `_current`).

## Integration points

### ConnectionsManager

**RULE-23**: `ConnectionsManager.set_peers_whitelist(whitelist)` MUST:

1. Stop the old whitelist (if any).
2. Set the new whitelist.
3. If the new whitelist is not `None`, start it with `drop_connection_by_peer_id`
   as the callback, then call `_disconnect_non_whitelisted_peers()`.

**RULE-24**: `_disconnect_non_whitelisted_peers()` MUST iterate all current
connections and force-disconnect any peer whose ID is not whitelisted
(reason: `"Whitelist updated"`). Peers with no ID yet (still handshaking) MUST
be skipped.

### Status API

**RULE-25**: The `/v1a/status` endpoint MUST include a `peers_whitelist` field
containing the list of currently whitelisted peer IDs as hex strings. If no
whitelist is active, the list MUST be empty.

### Sysctl

**RULE-26**: The sysctl key `p2p.connections.whitelist` MUST support get and set:

- **Get**: returns the source string (URL or file path) of the active whitelist,
  or `"none"` if no whitelist is active.
- **Set `"on"`**: restores the suspended whitelist. If no whitelist is suspended,
  this is a no-op.
- **Set `"off"`**: suspends the active whitelist (stores it in
  `_suspended_whitelist`), sets the active whitelist to `None`. If no whitelist
  is active, this is a no-op.
- **Set URL/path**: creates a new whitelist via `create_peers_whitelist()` and
  replaces the active one. If the spec resolves to `None`, MUST raise
  `SysctlException` (sysctl does not allow swapping to `None` — use `"off"`).
  Any previously suspended whitelist MUST be discarded.

**RULE-27**: The sysctl key `p2p.connections.whitelist.status` MUST be read-only
and return a `WhitelistStatus` with:

| Field | Type | Description |
|---|---|---|
| `state` | `WhitelistState` | `ON` (active), `OFF` (suspended), or `DISABLED` (never configured). |
| `policy` | `WhitelistPolicy \| None` | The policy of the whitelist (active or suspended). `None` if `DISABLED`. |
| `peer_count` | `int` | Number of peers in the whitelist. `0` if `DISABLED`. |
| `source` | `str \| None` | URL or file path. `None` if `DISABLED`. |

The status MUST reflect the suspended whitelist's data when state is `OFF`.

# Edge Cases & Decisions

**DEC-01: Grace period uses bootstrap peers, not open admission**
Decision: Before the first successful fetch, only peers discovered via
DNS/entrypoints (bootstrap peers) are allowed — not all peers.
Rationale: Open admission during grace period would allow connecting to
arbitrary peers before the authoritative list is loaded, defeating the purpose
of the whitelist during the most vulnerable window (startup).
Alternative rejected: Allow all peers during grace period. Rejected because it
creates a window for eclipse attacks at startup.

**DEC-02: Whitelist failures preserve the existing list**
Decision: When a fetch fails (network error, HTTP error, parse error), the
previously loaded whitelist remains in effect.
Rationale: Transient failures should not cause the node to either lock out all
peers (empty list) or admit all peers (no list). The last known good state is
the safest default.
Alternative rejected: Clear the whitelist on failure (too disruptive). Fall back
to allow-all on failure (defeats the security purpose).

**DEC-03: Identity-based whitelisting, not IP-based**
Decision: The whitelist operates on peer IDs (derived from public keys), not on
IP addresses.
Rationale: IP-based filtering is trivially bypassed via IP spoofing or NAT. Peer
IDs are cryptographically bound to the TLS handshake, so they cannot be forged.
The enforcement point is after the TLS+PEER-ID handshake, where the peer's
identity is verified.
Alternative rejected: IP-based filtering via netfilter. Rejected because
netfilter does not have peer-identity awareness at decision time.

**DEC-04: File I/O runs in a thread**
Decision: `FilePeersWhitelist` reads the file via `deferToThread`.
Rationale: The Twisted reactor is single-threaded. Blocking on file I/O (even
briefly) would stall all network operations. Thread delegation keeps the reactor
responsive.
Alternative rejected: Synchronous read in the reactor thread. Rejected because
even local file reads can block on NFS mounts or slow disks.

**DEC-05: Sysctl `off` suspends but does not destroy the whitelist**
Decision: `set_whitelist("off")` stores the current whitelist object internally
and sets the active whitelist to `None`. `set_whitelist("on")` restores it.
Rationale: Operators need a quick toggle for debugging or emergencies without
losing the configured source. A destroy-and-recreate cycle would require
re-specifying the URL/path.
Alternative rejected: Destroy the whitelist on `off`, require re-creation on
`on`. Rejected for poor operational ergonomics.

**DEC-06: Sysctl `on` re-runs enforcement immediately**
Decision: When the whitelist is re-enabled via sysctl `on`, the manager
immediately disconnects all peers not in the whitelist.
Rationale: Peers that connected while the whitelist was suspended should not
remain connected after enforcement resumes. Immediate enforcement prevents a
window where unauthorized peers persist.
Alternative rejected: Wait for the next refresh cycle. Rejected because it
creates a gap proportional to the refresh interval.

**DEC-07: The `allow-all` policy still tracks the peer list**
Decision: Under `allow-all`, the whitelist still fetches and stores the peer
set. It simply skips the membership check.
Rationale: This allows monitoring which peers are on the list without enforcing
it. Switching from `allow-all` to `only-whitelisted-peers` (by updating the
remote file) takes effect on the next refresh without any local action.

**DEC-08: Invalid peer IDs are skipped, not fatal**
Decision: A line that fails to parse as a peer ID is logged as a warning and
skipped. The rest of the whitelist is still applied.
Rationale: A single typo in a large whitelist should not block the entire
update. Operators can detect the issue via logs.
Alternative rejected: Reject the entire whitelist on any parse error. Rejected
because it makes the system too brittle for operational use.

**DEC-09: Factory resolves spec by probing the filesystem first**
Decision: `create_peers_whitelist` checks `os.path.isfile(spec)` before falling
back to URL interpretation.
Rationale: This allows operators to pass a plain path without any prefix. The
file check is unambiguous — if the file exists, it's a file source.
Alternative rejected: Require a `file://` prefix for file paths. Rejected for
unnecessary verbosity.

**DEC-10: Mainnet requires HTTPS for URL-based whitelists**
Decision: On mainnet, the URL MUST use `https` scheme.
Rationale: An HTTP whitelist can be MITM'd to inject arbitrary peer IDs,
defeating the security purpose.
Alternative rejected: Allow HTTP everywhere. Rejected for obvious security
reasons on production networks.

# Open Questions

- Should the grace period have a timeout after which the node falls back to open
  mode rather than remaining in bootstrap-only mode indefinitely?
- Should `on_remove_callback` be async to allow coordinating graceful
  disconnection (e.g. draining in-flight sync)?

# Changelog

| Date | Author | Description |
|------|--------|-------------|
| 2026-04-15 | Hathor Labs | Initial draft |
